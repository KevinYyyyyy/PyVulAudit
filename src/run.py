#!/usr/bin/env python3
"""
PyVulAudit - Python Vulnerability Audit Tool
Main entry point for the vulnerability audit system.

This tool performs comprehensive vulnerability analysis including:
1. Vulnerability data collection from OSV database
2. Patch analysis and code change detection
3. Reachability analysis for vulnerable functions
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / 'data_collection'))

from vulnerability_collector import VulnerabilityCollector
from patch_parser import PatchParser
from reachability_checker import ReachabilityChecker
from data_classes import VulnerablePackage, PackageInfo

# Import from data_collection
try:
    from data_collection.logger import logger
    from data_collection.constant import DATA_DIR, SUFFIX
except ImportError:
    # Fallback logging setup
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    DATA_DIR = Path("data")
    SUFFIX = ""


class PyVulAudit:
    """Main class for orchestrating vulnerability audit workflow"""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize PyVulAudit with configuration"""
        self.config = config or {}
        self.vulnerability_collector = VulnerabilityCollector()
        self.patch_parser = PatchParser()
        self.reachability_checker = ReachabilityChecker()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
    def collect_vulnerabilities(self, force_update: bool = False) -> Dict:
        """
        Collect vulnerability data from OSV database
        
        Args:
            force_update: Whether to force update even if cache exists
            
        Returns:
            Dictionary mapping CVE IDs to advisory data
        """
        logger.info("Starting vulnerability collection...")
        
        # Download OSV database if needed
        if force_update or not self.vulnerability_collector.osv_data_exists():
            self.vulnerability_collector.download_osv_database()
        
        # Load and process vulnerabilities
        cve2advisory = self.vulnerability_collector.load_cve_to_advisory_mapping()
        
        # Filter and process data
        filtered_data = self.vulnerability_collector.filter_vulnerabilities(cve2advisory)
        
        logger.info(f"Collected {len(filtered_data)} vulnerabilities")
        return filtered_data
        
    def analyze_patches(self, cve2advisory: Dict, target_cves: Optional[List[str]] = None) -> Dict:
        """
        Analyze patches and code changes for vulnerabilities
        
        Args:
            cve2advisory: CVE to advisory mapping
            target_cves: Specific CVEs to analyze (None for all)
            
        Returns:
            Analysis results with code changes and vulnerable functions
        """
        logger.info("Starting patch analysis...")
        
        if target_cves:
            filtered_cve2advisory = {
                cve: advisory for cve, advisory in cve2advisory.items() 
                if cve in target_cves
            }
        else:
            filtered_cve2advisory = cve2advisory
        
        # Collect commits for each CVE
        all_commits = {}
        for cve_id, advisory in filtered_cve2advisory.items():
            try:
                commits = self.patch_parser.collect_commits_for_cve(cve_id, advisory)
                if commits:
                    all_commits[cve_id] = commits
            except Exception as e:
                logger.warning(f"Failed to collect commits for {cve_id}: {e}")
                continue
        
        # Analyze code changes
        results = {}
        for cve_id, commits in all_commits.items():
            try:
                changes = self.patch_parser.analyze_code_changes(cve_id, commits)
                if changes:
                    results[cve_id] = changes
            except Exception as e:
                logger.warning(f"Failed to analyze changes for {cve_id}: {e}")
                continue
        
        logger.info(f"Analyzed patches for {len(results)} CVEs")
        return results
        
    def check_reachability(self, cve2advisory: Dict, analysis_results: Dict, 
                          dataset_size: str = 'small') -> Dict:
        """
        Check reachability of vulnerable functions
        
        Args:
            cve2advisory: CVE to advisory mapping
            analysis_results: Results from patch analysis
            dataset_size: Size of dataset to analyze ('small', 'medium', 'large')
            
        Returns:
            Reachability analysis results
        """
        logger.info("Starting reachability analysis...")
        
        # Convert analysis results to VulnerablePackage objects
        vulnerable_packages = []
        for cve_id, changes in analysis_results.items():
            if cve_id not in cve2advisory:
                continue
                
            advisory = cve2advisory[cve_id]
            
            # Extract package info from advisory
            package_name = advisory.get('package', {}).get('name', '')
            affected_versions = advisory.get('affected', [])
            
            if not package_name or not affected_versions:
                continue
            
            # Get vulnerable functions from changes
            vulnerable_functions = []
            upstream_modules = []
            
            if 'vulnerable_functions' in changes:
                vulnerable_functions = changes['vulnerable_functions']
            if 'modules' in changes:
                upstream_modules = changes['modules']
            
            # Use the first affected version for analysis
            version = affected_versions[0].get('version', '') if affected_versions else ''
            
            if version:
                vulnerable_packages.append(VulnerablePackage(
                    cve_id=cve_id,
                    package_name=package_name,
                    version=version,
                    vulnerable_functions=vulnerable_functions,
                    upstream_modules=upstream_modules
                ))
        
        # Limit dataset size
        size_limits = {'small': 10, 'medium': 50, 'large': 200}
        limit = size_limits.get(dataset_size, 10)
        vulnerable_packages = vulnerable_packages[:limit]
        
        # Perform batch reachability check
        reachability_results = self.reachability_checker.batch_check_reachability(
            vulnerable_packages
        )
        
        logger.info("Reachability analysis completed")
        return reachability_results
        
    def run_full_analysis(self, target_cves: Optional[List[str]] = None, 
                         dataset_size: str = 'small', 
                         force_update: bool = False) -> Dict:
        """
        Run complete vulnerability audit workflow
        
        Args:
            target_cves: Specific CVEs to analyze
            dataset_size: Size of dataset ('small', 'medium', 'large')
            force_update: Whether to force update cached data
            
        Returns:
            Complete analysis results
        """
        logger.info("Starting full vulnerability audit analysis...")
        
        # Step 1: Collect vulnerabilities
        cve2advisory = self.collect_vulnerabilities(force_update=force_update)
        
        # Step 2: Analyze patches
        patch_results = self.analyze_patches(cve2advisory, target_cves)
        
        # Step 3: Check reachability
        reachability_results = self.check_reachability(
            cve2advisory, patch_results, dataset_size
        )
        
        # Calculate summary statistics
        total_reachable = 0
        total_pairs = 0
        
        for cve_results in reachability_results.values():
            total_pairs += len(cve_results)
            total_reachable += sum(1 for result in cve_results if result.is_reachable)
        
        # Combine results
        results = {
            'vulnerabilities': cve2advisory,
            'patch_analysis': patch_results,
            'reachability': reachability_results,
            'summary': {
                'total_cves': len(cve2advisory),
                'analyzed_cves': len(patch_results),
                'reachability_pairs': total_pairs,
                'reachable_vulnerabilities': total_reachable,
                'reachability_rate': total_reachable / total_pairs if total_pairs > 0 else 0
            }
        }
        
        logger.info("Full analysis completed successfully")
        return results


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description='PyVulAudit - Python Vulnerability Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --collect                           # Collect vulnerabilities only
  %(prog)s --analyze --cve CVE-2023-12345     # Analyze specific CVE
  %(prog)s --full --size medium                # Full analysis on medium dataset
  %(prog)s --reachability --size large        # Reachability analysis only
        """
    )
    
    # Main operation modes
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--collect', action='store_true',
                      help='Collect vulnerability data only')
    group.add_argument('--analyze', action='store_true',
                      help='Analyze patches and code changes')
    group.add_argument('--reachability', action='store_true',
                      help='Check reachability of vulnerable functions')
    group.add_argument('--full', action='store_true',
                      help='Run complete analysis workflow')
    
    # Configuration options
    parser.add_argument('--cve', type=str, nargs='+',
                       help='Specific CVE IDs to analyze')
    parser.add_argument('--size', type=str, choices=['small', 'medium', 'large'],
                       default='small', help='Dataset size for analysis')
    parser.add_argument('--force-update', action='store_true',
                       help='Force update cached data')
    parser.add_argument('--log-level', type=str, 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')
    parser.add_argument('--output', type=str,
                       help='Output file for results (JSON format)')
    
    return parser


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create configuration
    config = {
        'log_level': args.log_level,
        'dataset_size': args.size,
        'force_update': args.force_update
    }
    
    # Initialize PyVulAudit
    audit_tool = PyVulAudit(config)
    
    try:
        results = None
        
        if args.collect:
            # Collect vulnerabilities only
            results = audit_tool.collect_vulnerabilities(args.force_update)
            
        elif args.analyze:
            # Analyze patches
            cve2advisory = audit_tool.collect_vulnerabilities()
            results = audit_tool.analyze_patches(cve2advisory, args.cve)
            
        elif args.reachability:
            # Check reachability
            cve2advisory = audit_tool.collect_vulnerabilities()
            patch_results = audit_tool.analyze_patches(cve2advisory, args.cve)
            results = audit_tool.check_reachability(
                cve2advisory, patch_results, args.size
            )
            
        elif args.full:
            # Full analysis
            results = audit_tool.run_full_analysis(
                target_cves=args.cve,
                dataset_size=args.size,
                force_update=args.force_update
            )
        
        # Output results
        if args.output and results:
            import json
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results saved to {output_path}")
        
        # Print summary
        if isinstance(results, dict) and 'summary' in results:
            summary = results['summary']
            print(f"\n=== Analysis Summary ===")
            print(f"Total CVEs: {summary['total_cves']}")
            print(f"Analyzed CVEs: {summary['analyzed_cves']}")
            if 'reachability_pairs' in summary:
                print(f"Reachability Pairs: {summary['reachability_pairs']}")
                print(f"Reachable Vulnerabilities: {summary['reachable_vulnerabilities']}")
                print(f"Reachability Rate: {summary['reachability_rate']:.2%}")
            else:
                print(f"Reachable Vulnerabilities: {summary.get('reachable_vulnerabilities', 0)}")
        elif isinstance(results, dict):
            print(f"\nProcessed {len(results)} items")
            
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
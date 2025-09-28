# Copyright [pythonJaRvis] [name of copyright owner]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import time
import formats
from jarvis import CallGraphGenerator
from utils.constants import CALL_GRAPH_OP, KEY_ERR_OP
import json

import sys
# print("Command line arguments:", sys.argv)
def main():
    # 在开头添加标准库路径确保unicodedata可访问
    import sys
    import os
    stdlib_path = f"{sys.prefix}/lib/python{sys.version_info.major}.{sys.version_info.minor}"
    if stdlib_path not in sys.path:
        sys.path.insert(0, stdlib_path)
    
    # 确保unicodedata模块可用
    try:
        import unicodedata
    except ImportError:
        raise RuntimeError("Failed to import unicodedata standard library module")
    start_time = time.time()

    parser = argparse.ArgumentParser()
    parser.add_argument("module",
                        nargs="*",
                        help="Modules to be processed")
    parser.add_argument(
        "--package",
        help="Package containing the code to be analyzed",
        default=None
    )
    parser.add_argument(
        "--decy",
        action="store_true",
        help="whether iterate the dependency",
        default=False
    )
    parser.add_argument(
        "--skip_builtin",
        action="store_true",
        help="whether skip python builtin modules",
        default=False
    )
    parser.add_argument(
        "--precision",
        action="store_true",
        help="whether flow-sensitive",
        default=False
    )
    parser.add_argument(
        "--entry_point",
        nargs="*",
        help="Entry Points to be processed",
        default=None
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output path",
        default=None
    )

    parser.add_argument(
        "-ext",
        "--external",
        help="External package path",
        nargs="*",
        default=None
    )
    args = parser.parse_args()
    if not args.module:
        raise Exception("Need Modules to be processed")

    # TODO: dynamic load packages
    print(args.module, args.package,args.decy,args.precision, args.entry_point,args.skip_builtin,'\n')
    cg = CallGraphGenerator(args.module, args.package, decy=args.decy,precision=args.precision, moduleEntry=args.entry_point,skip_builtin=args.skip_builtin)
    if args.external:
        cg.import_manager.add_external_path(args.external)
    cg.analyze()

    formatter = formats.Simple(cg)
    output = formatter.generate()
    # if args.operation == CALL_GRAPH_OP:
    #     if args.fasten:
    #         formatter = formats.Fasten(cg, args.package,
    #                                    args.product, args.forge, args.version, args.timestamp)
    #     else:
    #         formatter = formats.Simple(cg)
    #     output = formatter.generate()
    # else:
    #     output = cg.output_key_errs()
    output = formatter.generate()
    as_formatter = formats.AsGraph(cg)

    if args.output:
        with open(args.output, "w+") as f:
            f.write(json.dumps(output))
    else:
        print(json.dumps(output))
    


if __name__ == '__main__':
    main()

from ast import main
from fileinput import filename
import re
from urllib.parse import urlparse
import logging
from github import Github, GithubException,Commit
from urllib3.util.retry import Retry
from github.GithubException import BadCredentialsException
import random
from github.PaginatedList import PaginatedList
import json
import requests
from string import Template

from data_collection.logger import logger


def remove_anchor_query_from_url(url:str):
    parsed_url = urlparse(url)
    if len(parsed_url.fragment) != 0 or len(parsed_url.query) != 0:
        # remove anchor and query string from URL
        if len(parsed_url.fragment) != 0:
            url = url[: -(len(parsed_url.fragment) + 1)]
        if len(parsed_url.query) != 0:
            url = url[: -(len(parsed_url.query) + 1)]
        parsed_url = urlparse(url)

    # pull commit to commit
    # https://github.com/python/cpython/pull/103993/commits/c120bc2d354ca3d27d0c7a53bf65574ddaabaf3a
    # https://github.com/python/cpython/commit/c120bc2d354ca3d27d0c7a53bf65574ddaabaf3a
    if (pull_commit_match :=re.match(r'https?://github\.com/([\w-]+/[\w-]+)/pull/\d+/commits/([\da-f]+)',url ) ) is not None:
        repo_name = pull_commit_match.group(1)
        commit_hash = pull_commit_match.group(2)
        url = f'https://github.com/{repo_name}/commit/{commit_hash}'

    return url

def make_repo_commit_find_dict(url_list:list[str]) -> dict[str,bool]:
    table = {}
    for url in [remove_anchor_query_from_url(u) for u in url_list]:
        if (commit_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/commit/([\da-f]+)', url)) is not None:
            repo_name = commit_match.group(1)
            table[repo_name] = True
    return table

GITHUB_TOKENS = []
GITHUB_LIST = []
def add_github_token_and_check():
    global GITHUB_LIST,GITHUB_TOKENS
    for token in GITHUB_TOKENS:
        logger.info(f'Adding GitHub token {token}')
        GITHUB_LIST.append(Github(token,
                                  retry=Retry(total=None, backoff_factor= 0.1,
                                              status_forcelist=[403],)))  # 403 rate limit exceeded

    for idx,github in enumerate(GITHUB_LIST):
        try:
            github.get_repo('JetBrains/kotlin')
        except BadCredentialsException as e:
            logger.error(f'{GITHUB_TOKENS[idx]} GitHub Token has expired.')
            raise e

    logger.info(f'Initialize GtiHub instance from {len(GITHUB_TOKENS)} tokens')
# add_github_token_and_check()
def random_g() -> Github:
    # get GitHub instance randomly
    idx = random.randint(0, len(GITHUB_LIST) - 1)
    return GITHUB_LIST[idx]
def random_token() -> str:
    idx = random.randint(0, len(GITHUB_TOKENS) - 1)
    return GITHUB_TOKENS[idx]
def find_github_commits_from_pull(logger: logging.Logger, repo_name: str, pull_id: int):
    commit_urls = []
    try:
        repo = random_g().get_repo(repo_name)
        pull = repo.get_pull(pull_id)
        commits: PaginatedList[Commit] = pull.get_commits()
        for c in commits:
            commit_urls.append(c.html_url)
        return commit_urls
    except GithubException as e:
        if e.status == 404 or e.status == 502:
            return commit_urls
        logger.error(f'[Github Exception] Get pull info({repo_name}/{pull_id}) with unknown GithubException:{e}')
        raise e
def get_commit_detail(logger, repo_name,commit_hash):
    try:
        repo = random_g().get_repo(repo_name)
        commit = repo.get_commit(commit_hash)
        print(commit.__dict__)

        return commit
    except GithubException as e:
        if e.status == 404 or e.status == 502:
            return commit_urls
        logger.error(f'[Github Exception] Get pull info({repo_name}/{pull_id}) with unknown GithubException:{e}')
        raise e
def get_file_content(logger, path,commit_hash):
    try:
        repo = random_g().get_repo(repo_name)
        commit = repo.get_contents(commit_hash)
        return commit
    except GithubException as e:
        if e.status == 404 or e.status == 502:
            return commit_urls
        logger.error(f'[Github Exception] Get pull info({repo_name}/{pull_id}) with unknown GithubException:{e}')
        raise e
raw_find_pull_id_from_issue = """{
  repository(owner:"$repo_owner", name:"$repo_name"){
    url
    issue(number: $issue_number){
      state
      timelineItems(last:100,itemTypes:[CROSS_REFERENCED_EVENT,REFERENCED_EVENT,CLOSED_EVENT,CLOSED_EVENT]){
  			totalCount
        nodes{
          __typename
          ... on CrossReferencedEvent{
            id
            createdAt
            isCrossRepository
            source{
              ... on PullRequest{
                number
                id
                url
                state
              }
            }
          }
          ... on ReferencedEvent {
            isCrossRepository
            isDirectReference
            commit {
              url
            }
          }
          ... on ClosedEvent{
            closer{
              __typename
              ... on Commit{
                url
              }
              ... on PullRequest{
                number
                id
                url
                state
              }
            }
          }
        }
      }
    }
  }
}
"""

def format_query_find_pull_id_from_issue(repo: str, issue_number: int):
    repo_owner, name = repo.split('/')
    t = Template(raw_find_pull_id_from_issue)
    res = t.substitute({'repo_owner': repo_owner, 'repo_name': name, 'issue_number': issue_number})
    return res

def find_github_pull_and_commit_from_issue(logger: logging.Logger, repo: str, issue_number: int) -> (
        list[int], list[str]):
    pull_ids = []
    commit_urls = []

    query = format_query_find_pull_id_from_issue(repo, issue_number)
    github_token = random_token()
    retry_cnt = 10
    while retry_cnt > 0:
        retry_cnt -= 1
        try:
            res = requests.post('https://api.github.com/graphql', json={'query': query},
                                headers={'Authorization': f'bearer {github_token}'}, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f'github GraphQL {e}, retry left:{retry_cnt}')
            continue
        if res.status_code != 200:
            continue
        res_content: dict = json.loads(res.content)
        if 'errors' in res_content.keys():  # find error in GraphQL
            break

        issue = res_content['data']['repository']['issue']
        timeline_items = issue['timelineItems']
        total_items_cnt = timeline_items['totalCount']
        if total_items_cnt == 0 or issue['state'] == 'OPEN':  # issue still OPEN, skip!
            break
        # [CrossReferencedEvent, ReferencedEvent, ClosedEvent]
        # 1. we find possible PR or commits from ClosedEvent.
        find_from_close_event = False
        for n in timeline_items['nodes']:
            node_type = n['__typename']
            if node_type == 'ClosedEvent' and n['closer'] is not None:
                closer = n['closer']
                closer_type = closer['__typename']  # [Commit, PullRequest]
                assert closer_type in ['Commit', 'PullRequest']
                if closer_type == 'Commit':
                    commit_urls.append(closer['url'])
                    find_from_close_event = True
                elif closer_type == 'PullRequest':
                    if closer['state'] == 'MERGED':  # PR state: [OPEN, CLOSED, MERGED]
                        pull_ids.append(closer['number'])
                        find_from_close_event = True

        if find_from_close_event:
            break

        # 2. if not found, then find PR or commits from [CrossReferencedEvent, ReferencedEvent]
        for n in timeline_items['nodes']:
            node_type = n['__typename']
            if node_type == 'CrossReferencedEvent':  # get PR
                if n['isCrossRepository']:
                    continue
                # source maybe empty if reference an issue
                if len(n['source']) == 0 or n['source']['state'] != 'MERGED':
                    continue
                pull_ids.append(n['source']['number'])  # PR id
            elif node_type == 'ReferencedEvent':  # get commit
                if not (n['isCrossRepository'] == False and n['isDirectReference'] == True):
                    continue
                commit_urls.append(n['commit']['url'])

        if len(pull_ids) != 0 and len(commit_urls) != 0:
            # if we find PR and commits in an issue, we only select commits.
            # commits is more specific than PR.
            pull_ids = []

        break

    return pull_ids, commit_urls


def find_github_commits_from_issue(logger: logging.Logger, repo_name: str, issue_id: int,visited_pull_ids:list[int]):
    # it is difficult to locate commits in the comments of issue.
    # e.g. https://github.com/dagolden/Capture-Tiny/issues/16 , https://github.com/chanmix51/Pomm/issues/122 ,
    #      https://github.com/ZeusCart/zeuscart/issues/28 , https://github.com/Yeraze/ytnef/issues/49
    commit_urls = []
    pull_ids, issue_commit_urls = find_github_pull_and_commit_from_issue(logger, repo_name, issue_id)
    commit_urls.extend(issue_commit_urls)
    for pull_id in pull_ids:
        if pull_id not in visited_pull_ids:
            commit_urls.extend(find_github_commits_from_pull(logger, repo_name, pull_id))

    return commit_urls
def is_commit_url(url:str):
    if (commit_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/commit/([\da-f]+)', url)) is not None:
        return commit_match
    return False
def is_pull_url(url:str):
    if (pull_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/pull/([\da-f]+)', url)) is not None:
        return pull_match
    return False
def is_issue_url(url:str):
    if (issue_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/issues/([\da-f]+)', url)) is not None:
        return issue_match
    return False
def find_potential_commits_from_github(logger: logging.Logger, url: str, visited_pull_ids:list[int], find_commit_url:bool = False) :
    """
        if issue/pr and commit come together, we ony select commit url, and do not crawl through issue/pr.
    """
    # print('find_commit_url:',find_commit_url)
    url = remove_anchor_query_from_url(url)

    commit_urls = []

    # 1. find commit URL
    if (commit_hash := is_commit_url(url)):
        commit_urls.append(url)
        return ('commit',commit_urls)
    # 2. find pull URL, search the commit URL in it
    elif not find_commit_url and (pull_match := is_pull_url(url)):
        logger.info(f"Get commit url from pull info:{url}")
        repo_name = pull_match.group(1)
        pull_id = int(pull_match.group(2))
        visited_pull_ids.append(pull_id)
        found_urls = find_github_commits_from_pull(logger, repo_name, pull_id)
        commit_urls.extend(found_urls)
        logger.info(f'Found {len(found_urls)} commits from pull info:{url}')
        return ('pull',commit_urls)
    # 3. issue
    elif not find_commit_url and (issue_match:=is_issue_url(url)):
        repo_name = issue_match.group(1)
        issue_id = int(issue_match.group(2))
        found_urls = find_github_commits_from_issue(logger, repo_name, issue_id, visited_pull_ids)
        commit_urls.extend(found_urls)
        logger.info(f'Found {len(found_urls)} commits from pull info:{url}')
        return ('issue',commit_urls)
    # 4. project advisory
    # https://github.com/pytorch/serve/security/advisories/GHSA-hhpg-v63p-wp7w -> https://github.com/pytorch/serve/pull/3083 但是
    else:
        # 项目地址
        # https://github.com/python-pillow/Pillow
        # github/pypa advisory
        # https://github.com/pypa/advisory-database/tree/main/vulns/pillow/PYSEC-2020-76.yaml
        pass

    # if len(commit_urls) == 0 and not find_commit_url:
    #     logger.warning(f'[Github Commit not found] through {url}')

    return (None,commit_urls)


#! /usr/bin/python

import argparse
import subprocess
import sys
import urllib
import re
import requests
import json

# TODO: gather owners
# TODO: gather READMEs
# TODO: -M/-C for `git annotate`

REVIEW_URL_RE = re.compile('^Review URL: (.*)$', re.M)
BUG_EQ_RE = re.compile('^BUG=(.*)$', re.M)
DOCS_LINK_RE = re.compile(r'https://docs.google.com/\S*', re.M)
TODO_RE = re.compile(r'TODO\((?:(?:https?://)?crbug.com/)?([0-9]{3,})\)|TODO\([^)]*\): (?:(?:https?://)?crbug.com/)?([0-9]{3,})')

class WeightedSet(dict):
  """Similar to a set, but items are added with a weight, and those weights are
  summed. The resulting items can then be output in order by weight."""

  class Item(dict):
    def __init__(self):
      super(WeightedSet.Item, self).__init__()
      self.weight = 0.0

  def add(self, item, weight=1.0):
    item = self.setdefault(item, self.Item())
    item.weight += weight
    return item

  def set(self, item, k, v):
    item = self.setdefault(item, self.Item())
    item[k] = v

  def by_weight(self):
    item_list = sorted(
        self.items(),
        key=lambda item: item[1].weight,
        reverse=True)
    return item_list


class File:
  """Represents a file to be analyzed by Gatherer."""

  def __init__(self, filespec):
    parts = filespec.split('|')
    self.filename = parts.pop(0)
    self.line_ranges = parts


def git(*args):
  args = ('git',) + args
  try:
    result = subprocess.run(args, capture_output=True, check=True)
  except subprocess.CalledProcessError as e:
    print("Error calling git:", file=sys.stderr)
    print(e.stderr.decode('utf-8'), file=sys.stderr)
    raise e
  return result.stdout


class Crbug:
  """Interface to monorail."""

  base_uri = 'https://bugs.chromium.org'

  def get_csrf_token(self):
    "Scrape the HTML for the CSRF token"
    html = requests.get(self.base_uri).text
    for line in html.split('\n'):
      if line.startswith(" 'token': '"):
        return line.split("'")[3]
    raise RuntimeError("Could not find CSRF in Monorail HTML")

  def get_issue(self, id):
    csrf_token = self.get_csrf_token()
    url = urllib.parse.urljoin(self.base_uri, 'prpc/monorail.Issues/GetIssue')
    resp = requests.post(
        url,
        data=json.dumps({
          'issueRef': {
            'localId': id,
            'projectName': 'chromium',
          }
        }),
        headers={
            'accept': 'application/json',
            'content-type': 'application/json',
            'x-xsrf-token': csrf_token,
        },
    )
    if resp.status_code != 200:
      raise RuntimeError("Monorail responded with %s: %s" % (resp, resp.text))
    # strip the JSONP header
    data = json.loads(resp.text[4:])
    return data['issue']

  def list_comments(self, id):
    csrf_token = self.get_csrf_token()
    url = urllib.parse.urljoin(self.base_uri, 'prpc/monorail.Issues/ListComments')
    resp = requests.post(
        url,
        data=json.dumps({
          'issueRef': {
            'localId': id,
            'projectName': 'chromium',
          }
        }),
        headers={
            'accept': 'application/json',
            'content-type': 'application/json',
            'x-xsrf-token': csrf_token,
        },
    )
    if resp.status_code != 200:
      raise RuntimeError("Monorail responded with %s: %s" % (resp, resp.text))
    # strip the JSONP header
    data = json.loads(resp.text[4:])
    return data['comments']


class Gatherer:
  """Gather data about code."""

  def __init__(self):
    self.crbug = Crbug()

    self.people = WeightedSet()
    self.bugs = WeightedSet()
    self.commits = WeightedSet()
    self.docs_links = WeightedSet()
    self.docs_files = WeightedSet()

  def gather(self, filespec):
    file = File(filespec)
    self.gather_from_annotate(file)
    for sha in self.commits:
      self.gather_from_commit(sha)
    for bug in self.bugs:
      self.gather_from_bug(bug)

  def gather_from_annotate(self, file):
    self.log(f"Gathering git annotations for {file.filename}")
    sha = None
    headers = {}

    line_range_args = []
    for range in file.line_ranges:
      line_range_args.extend(['-L', range])
    for line in git('annotate', '-p', *line_range_args,
                    '--', file.filename).splitlines():
      line = line.decode('utf-8')
      if line.startswith('\t'):
        if headers:
          # weight commits by author_time, so newest are first
          author_time = int(headers['author-time'])
          commit = self.commits.add(sha, author_time)
          commit['author'] = f"{headers['author']} {headers['author-mail']}"
          commit['author-time'] = author_time
          commit['summary'] = headers['summary']
          self.people.add(commit['author'], 10.0) # 10 points per unique commit
          self.people.set(commit['author'], 'author', True)
        commit = self.commits[sha]
        self.people.add(commit['author'], 1.0) # 1 point per line
        sha = None
        continue

      if not sha:
        sha = line.split(' ', 1)[0]
        headers = {}
      else:
        k, v = line.split(' ', 1)
        headers[k] = v

  def gather_from_commit(self, sha):
    self.log(f"Gathering git commit information for {sha}")

    # Get the message body broken into "paragraphs" to separate out the
    # actual body and the headers.
    body = git('show', '-s', '--format=%B', sha)
    body = body.decode('utf-8').strip().split('\n\n')
    (body, headers) = (body[:-1], body[-1])
    body = '\n\n'.join(body)

    commit_headers = {}
    for header in headers.strip().splitlines():
      k, v = header.split(': ', 1)
      commit_headers.setdefault(k, []).append(v)

    commit = self.commits[sha]
    commit['body'] = body
    commit['commit-headers'] = commit_headers

    for reviewer in commit_headers.get('Reviewed-by', []):
      self.people.add(reviewer, 100.0) # lots of "points" for reviewing
      self.people.set(reviewer, 'reviewer', True)

    commit['cl'] = None
    if 'Reviewed-on' in commit_headers:
      commit['cl'] = commit_headers['Reviewed-on'][0]

    for bug in commit_headers.get('Bug', []):
      for bug in bug.split(','):
        bug = bug.strip()
        self.bugs.add(bug)

    self.gather_doc_links(body)

    # older commits used BUG= format and "Review URL:"
    if not commit['cl']:
      mo = REVIEW_URL_RE.search(body)
      if mo:
        commit['cl'] = mo.group(1)

    mo = BUG_EQ_RE.search(body)
    if mo:
      for bug in mo.group(1).split(','):
        bug = bug.strip()
        self.bugs.add(bug)

    diff = git('show', '--format=', sha).decode('utf-8')

    for line in diff.splitlines():
      if line.startswith('+'):
        # Look for added TODO lines with a bug in them
        mo = TODO_RE.search(line)
        if mo:
          for id in mo.groups():
            if id:
              self.bugs.add(id)

        # Look for links to design docs in the code
        self.gather_doc_links(line)

  def gather_doc_links(self, text):
    for link in DOCS_LINK_RE.findall(text):
      # remove fragments and queries
      link = link.split('#', 1)[0]
      link = link.split('?', 1)[0]
      # remove a trailing `/edit` or `/`
      link = re.sub('/(edit/?)?[.,]?$', '', link)
      self.docs_links.add(link)

      # try to get the title
      try:
        body = requests.get(link + '/edit').text
      except Exception:
        # oh well..
        return
      mo = re.search('<title>([^<]*)</title>', body)
      if mo:
        title = mo.group(1)
        if 'Sign-in' not in title:
          title = re.sub(' - Google Docs$', '', title)
          self.docs_links.set(link, 'title', title)

  def gather_from_bug(self, id):
    # if the bug is an integer, try loading it from crbug
    is_crbug = False
    try:
      int(id)
      is_crbug = True
    except Exception as e:
      is_crbug = False

    if is_crbug:
      self.gather_from_crbug(id)

  def gather_from_crbug(self, id):
    self.log(f"Gathering crbug information for {id}")
    try:
      issue = self.crbug.get_issue(int(id))
      comments = self.crbug.list_comments(int(id))
    except Exception as e:
      self.log(" (failed)")
      return

    for comment in comments:
      self.gather_doc_links(comment.get('content', ''))

    self.bugs.set(id, 'summary', issue['summary'])
    if 'ownerRef' in issue:
      self.bugs.set(id, 'owner', issue['ownerRef']['displayName'])
    self.bugs.set(id, 'link', 'https://crbug.com/' + id)

  def log(self, msg):
    print(msg, file=sys.stderr)

  def print_result(self):
    def header(title):
      print(f"\n## {title}\n")

    header("Commits")
    for (sha, commit) in self.commits.by_weight():
      print(f"* {sha[:9]} - {commit['summary']} ({commit['author']})")
      if commit['cl']:
        print(f"  on {commit['cl']}")

    header('People')
    print("_Key:_ A = author, R = reviewer")
    for ident, person in self.people.by_weight():
      author = 'A' if person.get('author', False) else ' '
      reviewer = 'R' if person.get('reviewer', False) else ' '
      print(f"* {author} {reviewer} - {ident}")

    if self.bugs:
      header('Bugs')
      for (id, bug) in self.bugs.by_weight():
        info = bug['link'] if 'link' in bug else id
        if 'summary' in bug:
          info = f"{info} - {bug['summary']}"
        print(f"* {info}")

    if self.docs_links:
      header('Docs Links')
      for (url, link) in self.docs_links.by_weight():
        if 'title' in link:
          print(f"* {url} - {link['title']}")
        else:
          print(f"* {url}")


def main():
  parser = argparse.ArgumentParser(
      usage="%(prog)s [OPTION] [FILE]...",
      description="Find links relating to the given files"
    )
  parser.add_argument(
      'files', nargs='*',
      help="""
        filename, or filename|linespec, where the linespec is that used in `git
        annotate`. Multiple linespecs can be included.
        """)
  args = parser.parse_args()

  if not args.files:
    parser.error("Must specify at least one file")

  gatherer = Gatherer()
  for filespec in args.files:
    gatherer.gather(filespec)
  gatherer.print_result()

if __name__ == "__main__":
  main()

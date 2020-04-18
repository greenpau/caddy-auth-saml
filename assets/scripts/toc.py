from pprint import pprint
from markdown import Markdown
from markdownify import markdownify
import re

with open('README.md', 'r') as fh:
    data = fh.read()
md = Markdown(extensions=['toc'])
md.convert(data)

toc = markdownify(md.toc, bullets="***")
toc_lines = toc.replace('\t', '  ').split('\n')
toc_lines = toc_lines[1:]
output = []
for line in toc_lines:
    line = re.sub('^\s{3}', '', line)
    if line == '':
        continue
    output.append(line)

print('<!-- begin-markdown-toc -->\n')
print('\n'.join(output))
print('<!-- end-markdown-toc -->\n')

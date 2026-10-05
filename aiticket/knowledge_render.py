"""Small escaped article formatter: headings, paragraphs, lists and inline emphasis."""
import re
from markupsafe import Markup,escape


def inline(text):
    text=str(escape(text))
    text=re.sub(r'`([^`\n]+)`',r'<code>\1</code>',text)
    return re.sub(r'\*\*([^*\n]+)\*\*',r'<strong>\1</strong>',text)


def render(body):
    blocks=[];paragraph=[];items=[];code=[];fenced=False
    def flush():
        if paragraph:blocks.append('<p>'+'<br>'.join(paragraph)+'</p>');paragraph.clear()
        if items:blocks.append('<ul>'+''.join('<li>'+x+'</li>' for x in items)+'</ul>');items.clear()
    for line in str(body).splitlines():
        if line.startswith('```'):
            flush()
            if fenced:blocks.append('<pre><code>'+str(escape('\n'.join(code)))+'</code></pre>');code=[]
            fenced=not fenced;continue
        if fenced:code.append(line);continue
        heading=re.match(r'^(#{1,4})\s+(.+)',line)
        if heading:
            flush();level=min(4,len(heading[1])+1);blocks.append(f'<h{level}>'+inline(heading[2])+f'</h{level}>')
        elif re.match(r'^\s*(?:[-*]|\d+\.)\s+',line):
            if paragraph:flush()
            items.append(inline(re.sub(r'^\s*(?:[-*]|\d+\.)\s+','',line)))
        elif not line.strip():flush()
        else:
            if items:flush()
            paragraph.append(inline(line))
    flush()
    if code:blocks.append('<pre><code>'+str(escape('\n'.join(code)))+'</code></pre>')
    return Markup(''.join(blocks))


def excerpt(body):
    text=re.sub(r'(?m)^\s*(?:#{1,6}|[-*]|\d+\.)\s*','',str(body))
    return ' '.join(text.replace('**','').replace('`','').split())[:180]

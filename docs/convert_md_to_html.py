#!/usr/bin/env python3
import os
import sys
import re
import subprocess

try:
    import markdown
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "markdown"])
    import markdown

def convert_md_to_html(md_file, html_file):
    """Convert markdown file to HTML."""
    print(f"Converting {md_file} to {html_file}")
    
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()
    
    # Convert markdown to HTML
    html_content = markdown.markdown(
        md_content,
        extensions=['tables', 'fenced_code', 'codehilite']
    )
    
    # Create a simple HTML template with basic styling
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIEM on Amazon OpenSearch Service</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #24292e;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        code {{
            background-color: rgba(27,31,35,.05);
            border-radius: 3px;
            font-family: SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace;
            font-size: 85%;
            margin: 0;
            padding: .2em .4em;
        }}
        pre {{
            background-color: #f6f8fa;
            border-radius: 3px;
            font-family: SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace;
            font-size: 85%;
            line-height: 1.45;
            overflow: auto;
            padding: 16px;
        }}
        a {{
            color: #0366d6;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
        }}
        table, th, td {{
            border: 1px solid #e1e4e8;
            padding: 6px 13px;
        }}
        thead {{
            background-color: #f6f8fa;
        }}
        img {{
            max-width: 100%;
        }}
        .back-to-home {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eaecef;
        }}
    </style>
</head>
<body>
    <div>{html_content}</div>
    <div class="back-to-home">
        <a href="index.html">← Back to Home</a>
    </div>
</body>
</html>
    """
    
    # Fix image paths in HTML content
    # Adjust this regex as needed based on your markdown image formatting
    html_template = re.sub(r'src="\./', 'src="', html_template)
    
    # Fix relative links to other .md files
    html_template = re.sub(r'href="([^"]+)\.md"', r'href="\1.html"', html_template)
    
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    return True

def process_directory(directory):
    """Process all markdown files in a directory."""
    success_count = 0
    failure_count = 0
    
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.md'):
                md_file = os.path.join(root, file)
                # Create HTML file with same name but .html extension
                html_file = md_file[:-3] + '.html'
                
                try:
                    if convert_md_to_html(md_file, html_file):
                        success_count += 1
                except Exception as e:
                    print(f"Error converting {md_file}: {e}")
                    failure_count += 1
    
    print(f"\nConversion completed: {success_count} files converted successfully, {failure_count} failures.")

if __name__ == "__main__":
    directory = "."  # Current directory (should be docs/)
    process_directory(directory)
    
    # Also convert README files in the repository root
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for readme_file in ["README.md", "README_ja.md", "README_zh-cn.md", "README_zh-tw.md"]:
        full_path = os.path.join(parent_dir, readme_file)
        if os.path.exists(full_path):
            html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.path.basename(full_path)[:-3] + '.html')
            try:
                convert_md_to_html(full_path, html_file)
                print(f"Converted root {readme_file} to docs/{os.path.basename(html_file)}")
            except Exception as e:
                print(f"Error converting root {readme_file}: {e}")

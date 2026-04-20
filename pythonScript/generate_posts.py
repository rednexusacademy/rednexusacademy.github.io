#!/usr/bin/env python3
"""
Red Nexus Academy Blog Scraper (Local File System Source)
Reads Markdown files directly from the local _posts folder.
Generates individual {slug}.js files and a metadata index.
"""

import json
import os
import re
from datetime import date, datetime
from pathlib import Path

import frontmatter
import markdown

# Configuration
BASE_URL = "https://rednexusacademy.github.io"  # Used for generating absolute URLs
POSTS_DIR = "_posts"                            # Folder containing .md files
OUTPUT_DIR = "generated"                        # Where .js files will be saved
METADATA_FILENAME = "blogPosts_metadata.js"
POSTS_SUBDIR = "posts"                          # Subdirectory for individual post files

def extract_slug_from_filename(filename: str) -> str:
    """Remove leading date (YYYY-MM-DD-) and .md extension."""
    return re.sub(r"^\d{4}-\d{2}-\d{2}-", "", filename).replace(".md", "")

def process_markdown_file(file_path: Path, post_id: int) -> dict:
    """Parse a single markdown file and return structured post data."""
    with open(file_path, 'r', encoding='utf-8') as f:
        post = frontmatter.load(f)

    metadata = post.metadata
    content_md = post.content
    slug = extract_slug_from_filename(file_path.name)

    # Metadata extraction
    title = metadata.get("title", "Untitled")
    description = metadata.get("description", "")
    date_val = metadata.get("date", "")
    if isinstance(date_val, (datetime, date)):
        # Both datetime and date have strftime
        date_str = date_val.strftime("%b %d, %Y")
    elif isinstance(date_val, str):
        date_str = date_val
    else:
        date_str = ""

    if not date_str:
        # Fallback: extract date from filename
        match = re.match(r"^(\d{4}-\d{2}-\d{2})", file_path.name)
        if match:
            date_str = datetime.strptime(match.group(1), "%Y-%m-%d").strftime("%b %d, %Y")
        
    categories = metadata.get("categories", [])
    if isinstance(categories, str):
        categories = [categories]
    tags = metadata.get("tags", [])
    if isinstance(tags, str):
        tags = [tags]

    image = None
    if "image" in metadata and isinstance(metadata["image"], dict):
        img_path = metadata["image"].get("path", "")
        if img_path:
            image = f"{BASE_URL}/{img_path.lstrip('/')}"

    url = f"{BASE_URL}/posts/{slug}/"

    # Convert Markdown to HTML
    md_converter = markdown.Markdown(extensions=['fenced_code', 'tables', 'toc'])
    content_html = md_converter.convert(content_md)

    # Extract images from content
    img_regex = r'!\[([^\]]*)\]\(([^)]+)\)'
    content_images = []
    for match in re.finditer(img_regex, content_md):
        alt = match.group(1)
        src = match.group(2)
        if not src.startswith('http'):
            src = f"{BASE_URL}/{src.lstrip('/')}"
        content_images.append({'src': src, 'alt': alt, 'title': alt})

    word_count = len(content_md.split())
    read_time = f"{max(1, round(word_count / 200))} min read"
    code_block_count = len(re.findall(r'```[\s\S]*?```', content_md))
    toc_html = getattr(md_converter, 'toc', '')

    post_data = {
        "id": post_id,
        "title": title,
        "description": description,
        "date": date_str,
        "image": image,
        "categories": categories,
        "tags": tags,
        "slug": slug,
        "url": url,
        "contentHtml": content_html,
        "contentMarkdown": content_md,
        "wordCount": word_count,
        "readTime": read_time,
        "codeBlockCount": code_block_count,
        "contentImages": content_images,
        "pin": metadata.get("pin", False),
        "math": metadata.get("math", False),
    }

    if toc_html:
        post_data["tableOfContents"] = toc_html

    return post_data

def save_posts_individually(posts, base_output_dir):
    """Save each post as a separate {slug}.js file."""
    posts_dir = os.path.join(base_output_dir, POSTS_SUBDIR)
    os.makedirs(posts_dir, exist_ok=True)

    for post in posts:
        filename = os.path.join(posts_dir, f"{post['slug']}.js")
        js_content = f"// Auto-generated post: {post['title']}\n"
        js_content += f"// Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        js_content += "export default "
        js_content += json.dumps(post, indent=2, ensure_ascii=False)
        js_content += ";\n"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(js_content)

    print(f"✓ Created {len(posts)} individual JS files in {posts_dir}")

def save_metadata_index(posts, base_output_dir):
    """Save metadata-only list for the blog index page."""
    list_version = []
    for post in posts:
        minimal = {k: v for k, v in post.items()
                   if k not in ['contentHtml', 'contentMarkdown', 'tableOfContents']}
        list_version.append(minimal)

    filename = os.path.join(base_output_dir, METADATA_FILENAME)
    js_content = "export const BLOG_POSTS_METADATA = " + json.dumps(list_version, indent=2, ensure_ascii=False) + ";\n"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(js_content)
    print(f"✓ Saved listing metadata to {filename}")

def main():
    print("=" * 60)
    print("LOCAL BLOG POST GENERATOR")
    print("=" * 60)

    posts_dir = Path(POSTS_DIR)
    if not posts_dir.exists():
        print(f"✗ Error: Directory '{POSTS_DIR}' not found.")
        return

    md_files = sorted(posts_dir.glob("*.md"))
    if not md_files:
        print(f"✗ No Markdown files found in '{POSTS_DIR}'.")
        return

    posts = []
    for idx, file_path in enumerate(md_files, start=1):
        print(f"  Processing {file_path.name}...")
        try:
            post_data = process_markdown_file(file_path, idx)
            posts.append(post_data)
        except Exception as e:
            print(f"    ✗ Error processing {file_path.name}: {e}")

    if not posts:
        print("✗ No posts were successfully processed.")
        return

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Save outputs
    save_metadata_index(posts, OUTPUT_DIR)
    save_posts_individually(posts, OUTPUT_DIR)

    print("\n✅ Generation complete!")
    print(f"Output written to '{OUTPUT_DIR}/'")
    print(f"Deploy: Copy the entire '{OUTPUT_DIR}' folder into your React 'src/data/' directory.")

if __name__ == "__main__":
    main()
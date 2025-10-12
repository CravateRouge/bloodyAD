import os
import re
import subprocess
import argparse

def run_cmd(cmd):
    """Run command and return stdout."""
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, text=True).stdout

def parse_commands(help_text):
    """Extract commands from the curly braces in the Commands section."""
    commands = []
    found = False
    for line in help_text.splitlines():
        if re.match(r'^Commands:', line.strip()):
            found = True
            continue
        if found:
            m = re.search(r'\{([^\}]+)\}', line)
            if m:
                commands = [c.strip() for c in m.group(1).split(',')]
            break
    if not found:
        raise Exception(f"Main Commands section not found in help text:\n\n{help_text}")
    else:
        print(f"Main Commands: {commands}")
    return commands

def parse_subcommands(help_text, command):
    """Extract subcommands for a given command from the help output."""
    subcommands = []
    found = False
    command_re = re.compile(rf'^{re.escape(command)} commands:', re.IGNORECASE)
    for line in help_text.splitlines():
        if command_re.match(line.strip()):
            found = True
            continue
        if found:
            m = re.search(r'\{([^\}]+)\}', line)
            if m:
                subcommands = [c.strip() for c in m.group(1).split(',')]
                break
    if not found:
        raise Exception(f"Command section for '{command}' not found in help text:\n\n{help_text}")
    else:
        print(f"Subcommands for '{command}': {subcommands}")
    return subcommands

def update_ps1_block(md, md_idx, section_level, section_name, cmd, new_output):
    """
    Find a section and ps1 block for block_header in md list, replace its content or insert if not found.
    Modify mutable md list and return cursor position.
    """
    # Compose regex for section and block
    # Section header can be '#', '##', or '###'
    # but '#' can also match comment in code so we don't match it
    level_pattern = rf'^#{{2,{len(section_level)}}} '
    section_header = section_level + " " + section_name
    section_pattern = rf"^{re.escape(section_header)}\s*$"
    new_block = f"```ps1\n$ {cmd}\n\n{new_output.strip()}\n```\n"

    # Find section line index
    section_idx = None
    idx = md_idx
    while idx < len(md):
        if re.match(section_pattern, md[idx].strip()):
            section_idx = idx
            break
        elif re.match(level_pattern, md[idx].strip()):  # Next section hitten
            print(f"Section '{section_header}' not found, adding before next section '{md[idx].strip()}'.")
            md.insert(idx, f"{section_header}\n{new_block}")
            return idx + 1
        idx += 1

    # If section not found, add at end
    if section_idx is None:
        print(f"Section '{section_header}' not found, adding at end.")
        md.append(f"{section_header}\n")
        section_idx = len(md) - 1

    # Search for ps1 block after section but before next section
    block_start = None
    block_end = None
    for idx in range(section_idx+1, len(md)):
        if md[idx].strip().startswith("```ps1"):
            # Check if it's the correct block (matches cmd)
            if idx+1 < len(md) and md[idx+1].strip().startswith(f"$"):
                block_start = idx
                # Find block end
                for j in range(idx+2, len(md)):
                    if md[j].strip() == "```":
                        block_end = j
                        break
                break

    # Replace or insert block
    if block_start is not None and block_end is not None:
        # Replace block
        md[block_start:block_end+1] = [new_block]
        md_idx = block_start + 1
    else:
        print(f"Block start '{block_start}' or block end '{block_end}' not found in {section_header}, inserting new block.")
        # Insert after section header (or at end)
        md.insert(section_idx+1, "\n" + new_block)
        md_idx = section_idx+1  # Move cursor after the newly inserted block
    return md_idx

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo-path', required=True)
    parser.add_argument('--wiki-path', required=True)
    parser.add_argument('--user-guide', default='User-Guide.md')
    args = parser.parse_args()

    bloody_args = f"bloodyAD -H 10.10.10.10 -d bloody -u admin -p pass"
    os.chdir(args.repo_path)

    # Load existing User-Guide.md (if exists)
    user_guide_path = os.path.join(args.wiki_path, args.user_guide)
    with open(user_guide_path, "r", encoding="utf-8") as f:
        md = f.readlines()
    md_idx = 0
    # 1. Global help
    global_help = run_cmd("bloodyAD -h")
    if not global_help:
        raise Exception("Failed to get global help from bloodyAD")
    md_idx = update_ps1_block(
        md,
        md_idx,
        "#","Global Arguments",
        "bloodyAD -h",
        global_help
    )

    # # Get into commands section
    # while True:
    #     if re.match(r'^# Commands Arguments', md[md_idx].strip()):
    #         md_idx += 1
    #         break
    #     md_idx += 1

    # 2. Parse commands
    commands = parse_commands(global_help)

    for command in commands:
        # 3. Command help
        cmd_help_cmd = f"{bloody_args} {command} -h"
        cmd_help = run_cmd(cmd_help_cmd)
        md_idx = update_ps1_block(
            md,
            md_idx,
            "##",f"{command} Commands",
            cmd_help_cmd,
            cmd_help
        )

        # 4. Parse subcommands
        subcommands = parse_subcommands(cmd_help, command)
        for subcommand in subcommands:
            sub_help_cmd = f"{bloody_args} {command} {subcommand} -h"
            sub_help = run_cmd(sub_help_cmd)
            md_idx = update_ps1_block(
                md,
                md_idx,
                "###", f"{command} {subcommand}",
                sub_help_cmd,
                sub_help
            )

    # Write back as Markdown
    with open(user_guide_path, "w", encoding="utf-8") as f:
        f.writelines(md)

if __name__ == "__main__":
    main()
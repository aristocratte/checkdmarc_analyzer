# Generate a visualization of json subfinder scan 

import os
import json
import pandas as pd
import graphviz as gv

def visualize_subdomains(json_file, output_file):
    subdomains = []
    
    # Read the JSON file line by line (JSONL format)
    with open(json_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data)
                except json.JSONDecodeError:
                    continue
    
    if not subdomains:
        print("No valid subdomain data found in the file.")
        return
    
    # Create a directed graph
    dot = gv.Digraph(comment='Subdomain Visualization')
    dot.attr(rankdir='TB')  # Top to Bottom layout
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')
    
    # Group subdomains by domain
    domain_groups = {}
    for item in subdomains:
        host = item.get('host', '')
        input_domain = item.get('input', '')
        source = item.get('source', '')
        
        if not host or not input_domain:
            continue
            
        if input_domain not in domain_groups:
            domain_groups[input_domain] = []
        domain_groups[input_domain].append({
            'host': host,
            'source': source
        })
    
    # Create visualization
    for domain, hosts in domain_groups.items():
        # Add root domain node
        dot.node(domain, domain, fillcolor='lightcoral', shape='ellipse')
        
        # Group by source for better organization
        source_groups = {}
        for host_info in hosts:
            source = host_info['source']
            if source not in source_groups:
                source_groups[source] = []
            source_groups[source].append(host_info['host'])
        
        # Add subdomains grouped by source
        for source, host_list in source_groups.items():
            # Create a subgraph for each source
            with dot.subgraph(name=f'cluster_{source}') as source_subgraph:
                source_subgraph.attr(label=f'Source: {source}', style='dashed')
                
                for host in host_list:
                    if host != domain:  # Don't add the root domain again
                        # Color nodes based on subdomain depth
                        parts = host.split('.')
                        domain_parts = domain.split('.')
                        depth = len(parts) - len(domain_parts)
                        
                        if depth <= 1:
                            color = 'lightgreen'
                        elif depth == 2:
                            color = 'lightyellow'
                        else:
                            color = 'lightpink'
                        
                        source_subgraph.node(host, host, fillcolor=color)
                        dot.edge(domain, host, label=source, fontsize='8')
    
    # Render the graph
    dot.render(output_file, format='png', cleanup=True)

def visualize_subdomains_simple(json_file, output_file):
    """Create a simple visualization without source grouping"""
    subdomains = []
    
    # Read the JSON file line by line (JSONL format)
    with open(json_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    subdomains.append(data)
                except json.JSONDecodeError:
                    continue
    
    if not subdomains:
        print("No valid subdomain data found in the file.")
        return
    
    # Create a simple directed graph
    dot = gv.Digraph(comment='Simple Subdomain Visualization')
    dot.attr(rankdir='TB')
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')
    
    # Get unique domains and hosts
    domains = set()
    hosts = set()
    
    for item in subdomains:
        host = item.get('host', '')
        input_domain = item.get('input', '')
        
        if host and input_domain:
            domains.add(input_domain)
            hosts.add(host)
    
    # Add nodes and edges
    for domain in domains:
        dot.node(domain, domain, fillcolor='lightcoral', shape='ellipse')
    
    for item in subdomains:
        host = item.get('host', '')
        input_domain = item.get('input', '')
        
        if host and input_domain and host != input_domain:
            dot.node(host, host)
            dot.edge(input_domain, host)
    
    # Render the graph
    dot.render(output_file, format='png', cleanup=True)
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Visualize subdomains from a subfinder JSON output file.')
    parser.add_argument('json_file', help='Path to the subfinder JSON output file')
    parser.add_argument('output_file', help='Output file name for the visualization (without extension)')
    parser.add_argument('--simple', action='store_true', help='Create a simple visualization without source grouping')

    args = parser.parse_args()

    if not os.path.exists(args.json_file):
        print(f"Error: File {args.json_file} not found.")
        exit(1)

    try:
        if args.simple:
            visualize_subdomains_simple(args.json_file, args.output_file)
        else:
            visualize_subdomains(args.json_file, args.output_file)
        print(f"Visualization saved to {args.output_file}.png")
    except Exception as e:
        print(f"Error creating visualization: {e}")
        exit(1)

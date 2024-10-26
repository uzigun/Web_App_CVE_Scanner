import requests
import gzip
import json
import glob
import subprocess
import re
import os

# Constants
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz"
START_YEAR = 2018
END_YEAR = 2024
JSON_DIR = r"C:\Users\vboxuser\Jsons"
OUTPUT_FILE = os.path.join(JSON_DIR, 'extracted_cve_ids.txt')
CATEGORIES_OUTPUT_FILE = os.path.join(JSON_DIR, 'cve_ids_by_technology.txt')
FILTERED_CVES_FILE = os.path.join(JSON_DIR, 'filtered_cves.txt')
FINAL_OUTPUT_FILE = os.path.join(JSON_DIR, 'res-output.txt')
NUCLEI_TEMPLATE_DIR = r'C:\Users\vboxuser\nuclei-templates'

# Download CVE data
def download_cve_data(year):
    url = BASE_URL.format(year)
    response = requests.get(url)
    if response.status_code == 200:
        with open(f"nvdcve-1.1-{year}.json.gz", "wb") as f:
            f.write(response.content)
        print(f"Downloaded CVE data for year {year}.")
    else:
        print(f"Failed to download CVE data for year {year}.")

# Extract and save CVE IDs
def extract_cve_ids():
    cve_ids = []
    json_files = glob.glob(os.path.join(JSON_DIR, "*.json"))

    for file in json_files:
        with open(file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if 'CVE_Items' in data:
                for item in data['CVE_Items']:
                    cve_id = item['cve']['CVE_data_meta']['ID']
                    cve_ids.append(cve_id)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as output_file:
        for cve_id in cve_ids:
            output_file.write(cve_id + '\n')

    print(f"Extracted {len(cve_ids)} CVE IDs to '{OUTPUT_FILE}'.")

# Categorize CVEs by technology
def categorize_cves():
    technologies = {
        "Django": ["django", "python", "django-admin", "django-rest-framework"],
        "Flask": ["flask", "werkzeug", "jinja"],
        "Ruby on Rails": ["rails", "ruby", "gem", "activerecord"],
        "Node.js": ["node", "express", "npm", "javascript"],
        "PHP": ["php", "laravel", "symfony", "codeigniter", "wordpress", "drupal"],
        "ASP.NET": ["asp.net", "dotnet", "c#"],
        "Java": ["java", "spring", "struts", "jsp", "hibernate"],
        "Angular": ["angular", "angularjs", "typescript"],
        "React": ["react", "jsx", "redux"],
        "Vue.js": ["vue", "vuejs"],
        "Go": ["go", "golang", "gin", "beego"],
        "WordPress": ["wordpress", "wp", "plugin", "theme"],
        "Apache": ["apache", "httpd"],
        "Nginx": ["nginx"],
        "Redis": ["redis"],
        "MongoDB": ["mongodb"],
        "PostgreSQL": ["postgresql", "pg"],
        "MySQL": ["mysql", "mariadb"],
    }

    cve_data = []
    json_files = glob.glob(os.path.join(JSON_DIR, "*.json"))

    for file in json_files:
        with open(file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if 'CVE_Items' in data:
                for item in data['CVE_Items']:
                    cve_info = {
                        'id': item['cve']['CVE_data_meta']['ID'],
                        'description': item['cve'].get('description', {}).get('description_data', [{}])[0].get('value', ''),
                        'references': [ref['url'] for ref in item['cve'].get('references', {}).get('reference_data', [])]
                    }
                    cve_data.append(cve_info)

    categorized_cves = {tech: [] for tech in technologies.keys()}
    
    for cve in cve_data:
        description = cve['description'].lower()
        references = [ref.lower() for ref in cve['references']]
        for tech, keywords in technologies.items():
            if any(keyword in description for keyword in keywords) or any(keyword in ref for ref in references for keyword in keywords):
                categorized_cves[tech].append(cve['id'])

    with open(CATEGORIES_OUTPUT_FILE, 'w') as output_file:
        for tech, cve_ids in categorized_cves.items():
            output_file.write(f"{tech}:\n")
            for cve_id in cve_ids:
                output_file.write(f"  - {cve_id}\n")
            output_file.write("\n")

    print("CVE IDs categorized by technology.")

# Extract CVE IDs from a text file
def extract_cve_ids_from_text():
    with open(CATEGORIES_OUTPUT_FILE, 'r') as f:
        content = f.read()

    cve_ids = re.findall(r'CVE-\d{4}-\d+', content)

    with open(FILTERED_CVES_FILE, 'w') as f:
        for cve_id in cve_ids:
            f.write(cve_id + '\n')

    print(f'Extracted CVE IDs: {cve_ids}')

# Load CVEs from a file
def load_cves(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

# Filter CVEs based on the year
def filter_cves(cve_list, start_year, end_year):
    cve_year_mapping = {f"CVE-{year}-XXXX": year for year in range(START_YEAR, END_YEAR + 1)}
    return [cve for cve in cve_list if cve in cve_year_mapping and start_year <= cve_year_mapping[cve] <= end_year]

# Run Nuclei scan
def run_nuclei_scan(target_url):
    all_cves = load_cves(FILTERED_CVES_FILE)
    filtered_cves = filter_cves(all_cves, START_YEAR, END_YEAR)

    if not filtered_cves:
        print("No CVEs found for the specified range.")
        return

    with open(FILTERED_CVES_FILE, 'w') as f:
        for cve in filtered_cves:
            f.write(f"{cve}\n")

    command = [
        'nuclei',
        '-u', target_url,
        '-l', FILTERED_CVES_FILE,
        '-t', NUCLEI_TEMPLATE_DIR,
        '-o', FINAL_OUTPUT_FILE,
        '-v'
    ]

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Nuclei scan completed successfully.")
        for cve in filtered_cves:
            if cve in result.stdout:
                print(f"The target is vulnerable to {cve}.")
                print("Detailed output:\n", result.stdout)
                break
        else:
            print("The target is not vulnerable to any of the specified CVEs.")
    except subprocess.CalledProcessError as e:
        print(f"Error during Nuclei scan: {e.stderr}")

def main():
    # Download CVE data for each year
    for year in range(START_YEAR, END_YEAR + 1):
        download_cve_data(year)

    # Extract CVE IDs from downloaded JSON files
    extract_cve_ids()

    # Categorize CVEs by technology
    categorize_cves()

    # Extract CVE IDs from categorized file
    extract_cve_ids_from_text()

    # Get target URL from user and run Nuclei scan
    target_url = input("Enter the target URL (e.g., https://example.com): ")
    run_nuclei_scan(target_url)

    print("All tasks completed.")

if __name__ == "__main__":
    main()

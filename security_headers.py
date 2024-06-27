"""
Security Headers scanner
"""
import re
import requests
from bs4 import BeautifulSoup


# Information to be collected
headlines = [
    "Missing Headers",
    "Warnings",
    # "Raw Headers",  # If commented out, then different URLs
    #                 # with the same security headers are combined
    "Upcoming Headers",
    "Additional Information"
]


# File with target URLs
URLS_FILE_PATH = "./urls.txt"
# URL to the Security Headers service
SECURITYHEADERS_URL = "https://securityheaders.com/"


def security_headers_scan(urls_file_path: str) -> dict:
    """
    Scan URLs for Security Headers

    :param urls_file_path: Path to text file containing the URLs
    :return: Security Headers to URLs mapping
    """
    security_headers_queries_mapping = {}
    with open(file=urls_file_path, encoding="utf-8") as file:
        for query in file.readlines():
            query_url = query.strip()
            security_headers_string = ""
            res = requests.get(url=f"{SECURITYHEADERS_URL}?q={query_url}&hide=on")
            soup = BeautifulSoup(res.text, "html.parser")
            for headline in headlines:
                div_tag = soup.find_all(string=re.compile(headline))
                if div_tag.__len__() != 1:
                    print(f"[!] Too many or too few div tags found for "
                          f"headline '{headline}' on url: '{query_url}'")
                    continue
                tr_tags = div_tag[0].parent.parent.find_all("tr")
                if tr_tags.__len__() == 0:
                    raise Exception("Too few tr tags found")
                security_headers_string += f"## {headline}\n"
                for tr_tag in tr_tags:
                    security_headers_string += (f"{tr_tag.next.text:<40}"
                                                f"{tr_tag.next.nextSibling.text}\n")
                security_headers_string += "\n"
            security_headers_string += "\n"
            if security_headers_string not in security_headers_queries_mapping:
                security_headers_queries_mapping[security_headers_string] = [query_url]
            else:
                security_headers_queries_mapping[security_headers_string].append(query_url)
    return security_headers_queries_mapping


def print_security_headers(security_headers_queries_mapping: dict) -> None:
    """
    Prints Security Headers for the different URLs

    :param security_headers_queries_mapping: Security Headers to URLs mapping
    """
    for security_headers, queries in security_headers_queries_mapping.items():
        print("# URLs")
        for query in queries:
            print(f"- {query}")
        print()
        print(security_headers)


if __name__ == "__main__":
    print_security_headers(
        security_headers_queries_mapping=security_headers_scan(urls_file_path=URLS_FILE_PATH)
    )

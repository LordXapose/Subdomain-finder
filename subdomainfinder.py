import tkinter as tk
import requests

class DomainSubdomainFinder:
    def __init__(self, master):
        self.master = master
        master.title("Domain & Subdomain Finder")

        self.domain_label = tk.Label(master, text="Enter Domain:")
        self.domain_label.pack()

        self.domain_entry = tk.Entry(master)
        self.domain_entry.pack()

        self.find_button = tk.Button(master, text="Find Subdomains", command=self.find_subdomains)
        self.find_button.pack()

        self.result_label = tk.Label(master, text="")
        self.result_label.pack()

    def find_subdomains(self):
        domain = self.domain_entry.get()
        subdomains = self.perform_subdomain_search(domain)
        self.result_label.config(text="\n".join(subdomains))

    def perform_subdomain_search(self, domain):
        url

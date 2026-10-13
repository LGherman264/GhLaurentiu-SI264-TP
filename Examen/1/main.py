from checker_B import SITES, build_url, is_https, show_response, check_site, scan_sites, check_headers, retry_check

# Partea 1
print("Partea 1, build_url:", build_url("example.com", "login"))
print("Partea 1, build_url:", build_url("example.com", "/login"))
print("Partea 1, is_https:", is_https("https://example.com"))
print("Partea 1, is_https:", is_https("http://example.com"))

# Partea 2
print("Partea 2, example.com:")
show_response("https://example.com")
print("Partea 2, inaccesibil:")
show_response("http://this-site-does-not-exist.invalid")

# Partea 3
print("Partea 3, site bun:", check_site("https://example.com"))
print("Partea 3, site inexistent:", check_site("http://this-site-does-not-exist.invalid"))

# Partea 4
print("Partea 4:")
scan_sites()

# Partea 5
print("Partea 5, cu antete:", check_headers(SITES[10]))
print("Partea 5, inaccesibil:", check_headers("http://this-site-does-not-exist.invalid"))

# Partea 6
print("Partea 6, 200:", retry_check("https://httpbin.org/status/200"))
print("Partea 6, 404:", retry_check("https://httpbin.org/status/404"))
print("Partea 6, 500:", retry_check("https://httpbin.org/status/500"))
print("Partea 6, inexistent:", retry_check("http://this-site-does-not-exist.invalid"))

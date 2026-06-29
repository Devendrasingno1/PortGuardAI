def identify_attack_surface(open_ports: list[dict]) -> list[str]:
    surfaces = set()

    for item in open_ports:
        port = item["port"]

        if port in [80, 443, 8080]:
            surfaces.add("Web Services")
        elif port in [22, 3389]:
            surfaces.add("Remote Access")
        elif port in [445, 139]:
            surfaces.add("File Sharing")
        elif port in [3306]:
            surfaces.add("Database Services")
        elif port in [21]:
            surfaces.add("File Transfer")
        elif port in [25, 110, 143]:
            surfaces.add("Mail Services")

    if not surfaces:
        surfaces.add("No major attack surface detected")

    return sorted(list(surfaces))
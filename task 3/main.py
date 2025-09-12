from modules import port_scanner, brute_forcer

def main():
    print("\n=== Penetration Testing Toolkit ===\n")
    print("1. Port Scanner")
    print("2. SSH Brute-Forcer")
    print("0. Exit")

    choice = input("\nChoose a module: ")

    if choice == "1":
        target = input("Enter target IP: ")
        open_ports = port_scanner.scan_ports(target)
        print("\nOpen ports:", open_ports)
    elif choice == "2":
        target = input("Enter target IP: ")
        user = input("Enter username: ")
        passwords = input("Enter passwords (comma-separated): ").split(",")
        found = brute_forcer.ssh_brute_force(target, user, passwords)
        if found:
            print(f"\nPassword found: {found}")
        else:
            print("\nPassword not found")
    elif choice == "0":
        print("Exiting...")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()

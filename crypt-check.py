import paramiko

class SSHCryptoAnalyzer:
    """
    A class to analyze cryptographic algorithms used by an SSH server.

    Attributes:
    host (str): The hostname or IP address of the SSH server.
    port (int): The port number of the SSH server (default is 22).
    username (str): The SSH username for authentication.
    password (str): The SSH password for authentication.
    client (paramiko.SSHClient): The SSH client used to connect to the server.
    """
    
    def __init__(self, host, port=22, username="your-username", password="your-password"):
        """
        Initializes the SSHCryptoAnalyzer with the server details.

        Args:
        host (str): The hostname or IP address of the SSH server.
        port (int): The port of the SSH server (default is 22).
        username (str): The SSH username for authentication.
        password (str): The SSH password for authentication.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None

    def connect(self):
        """
        Connects to the SSH server using the provided credentials.

        This method establishes an SSH connection to the server and prepares the client for further operations.

        Raises:
        Exception: If the connection to the SSH server fails.
        """
        try:
            # Initialize Paramiko SSH client
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect to the SSH server
            print(f"Connecting to {self.host}:{self.port}...")
            self.client.connect(self.host, port=self.port, username=self.username, password=self.password)
        except Exception as e:
            raise Exception(f"Failed to connect to {self.host}:{self.port} - {e}")

    def get_crypto_info(self):
        """
        Retrieves the cryptographic algorithms used in the SSH connection.

        This method retrieves the key exchange (KEX), cipher, MAC (message authentication code), 
        compression algorithms, and key types used by the SSH connection.

        Returns:
        dict: A dictionary containing the cryptographic algorithms used in the SSH session.
        
        Raises:
        Exception: If no transport layer is established.
        """
        transport = self.client.get_transport()
        
        # Ensure a transport layer has been established
        if not transport:
            raise Exception("No transport layer established")

        # Retrieve security options, including algorithms
        security_options = transport.get_security_options()

        # Return a dictionary of cryptographic algorithms
        return {
            "kex": security_options.kex,
            "ciphers": security_options.ciphers,
            "digests": security_options.digests,
            "compression": security_options.compression,
            "key_types": security_options.key_types
        }

    def analyze_crypto(self, crypto_info):
        """
        Analyzes the cryptographic algorithms used and provides suggestions for stronger alternatives.

        This method checks the algorithms used (KEX, cipher, and MAC) and compares them against
        known weak algorithms. If weak algorithms are found, it provides suggestions for better alternatives.

        Args:
        crypto_info (dict): A dictionary containing the cryptographic algorithms used.

        Returns:
        list: A list of suggestions for improving cryptographic strength if weak algorithms are detected.
        """
        weak_algorithms = {
            "kex": {
                "diffie-hellman-group1-sha1": "Weak (logjam attack) - Consider using diffie-hellman-group14-sha256 or stronger",
                "diffie-hellman-group14-sha1": "Weak - Use diffie-hellman-group14-sha256 or stronger",
            },
            "ciphers": {
                "aes128-cbc": "Weak - Vulnerable to padding oracle attacks, consider using aes128-ctr or aes256-ctr",
                "3des-cbc": "Weak - Vulnerable, use aes128-ctr or aes256-ctr",
                "arcfour": "Weak - Deprecated, consider using aes128-ctr or aes256-ctr",
            },
            "digests": {
                "hmac-sha1": "Weak - Consider using hmac-sha2-256 or higher",
                "hmac-md5": "Weak - Use hmac-sha2-256 or higher",
            }
        }

        suggestions = []

        # Check for weak Key Exchange algorithms and suggest alternatives
        for kex in crypto_info["kex"]:
            if kex in weak_algorithms.get("kex", {}):
                suggestions.append(f"KEX: {kex} - {weak_algorithms['kex'][kex]}")

        # Check for weak Cipher algorithms and suggest alternatives
        for cipher in crypto_info["ciphers"]:
            if cipher in weak_algorithms.get("ciphers", {}):
                suggestions.append(f"Cipher: {cipher} - {weak_algorithms['ciphers'][cipher]}")

        # Check for weak Digest algorithms and suggest alternatives
        for digest in crypto_info["digests"]:
            if digest in weak_algorithms.get("digests", {}):
                suggestions.append(f"Digest: {digest} - {weak_algorithms['digests'][digest]}")

        return suggestions

    def close(self):
        """
        Closes the SSH connection.

        This method closes the SSH connection to the server and releases any resources.
        """
        if self.client:
            self.client.close()

    def run(self):
        """
        Runs the analysis, retrieves cryptographic information, and provides suggestions.

        This method connects to the server, retrieves the cryptographic information, 
        analyzes the algorithms used, and prints suggestions for improvement.
        """
        self.connect()

        # Retrieve cryptographic algorithms used in the connection
        crypto_info = self.get_crypto_info()

        # Print the algorithms used during the connection
        print("Key Exchange Algorithms:", ", ".join(crypto_info["kex"]))
        print("Ciphers:", ", ".join(crypto_info["ciphers"]))
        print("Digests:", ", ".join(crypto_info["digests"]))
        print("Compression:", ", ".join(crypto_info["compression"]))
        print("Key Types:", ", ".join(crypto_info["key_types"]))

        # Analyze cryptographic algorithms and provide suggestions
        suggestions = self.analyze_crypto(crypto_info)

        # Print cryptographic analysis and suggestions
        print("\nCryptographic Analysis and Suggestions:")
        if not suggestions:
            print("No cryptographic issues found.")
        else:
            for suggestion in suggestions:
                print(f"- {suggestion}")

        self.close()

# Usage example:
if __name__ == "__main__":
    host = "localhost"  # Replace with your SSH server address
    username = "minl"  # Replace with your SSH username
    password = "5131"  # Replace with your SSH password
    analyzer = SSHCryptoAnalyzer(host, username=username, password=password)
    try:
        analyzer.run()
    except Exception as e:
        print(f"Error: {e}")
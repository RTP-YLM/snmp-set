from pysnmp.hlapi import *
import csv
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString

# Define the file paths
target_ips_file = 'target_ips.txt'
oid_files = ['oid1.txt', 'oid2.txt']  # Add additional OID file paths here
value_files = ['value1.txt', 'value2.txt']  # Add additional value file paths here
value_type_files = ['value_type1.txt', 'value_type2.txt']  # Add additional value type file paths here
log_file = 'snmp_set_results.csv'

# Read target IPs from the file
with open(target_ips_file, 'r', encoding='utf-8') as file:
    target_ips = [line.strip() for line in file]

# Open CSV file for writing logs
with open(log_file, 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['Target_IP', 'OID', 'Value', 'Result']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    # Iterate over target IPs
    for target_ip in target_ips:
        # Iterate over OID files, value files, and value type files simultaneously
        for oid_file, value_file, value_type_file in zip(oid_files, value_files, value_type_files):
            try:
                # Read OID from the file
                with open(oid_file, 'r', encoding='utf-8') as file:
                    oid = file.read().strip()

                # Read value from the file
                with open(value_file, 'r', encoding='utf-8') as file:
                    value = file.read().strip()

                # Read value type from the file
                with open(value_type_file, 'r', encoding='utf-8') as file:
                    value_type = file.read().strip()

                # Convert value to the appropriate SNMP data type based on value type
                if value_type.lower() == 'integer':
                    value = Integer(int(value))
                elif value_type.lower() == 'ipaddress':
                    value = IpAddress(value)
                elif value_type.lower() == 'string':
                    value = OctetString(value)
                else:
                    print(
                        "Invalid value type specified in the file. Supported types: 'integer', 'IPAddress', 'String'.")
                    continue

                # Build SNMP SET request
                set_command = setCmd(
                    SnmpEngine(),
                    CommunityData('public'),  # SNMP community string
                    UdpTransportTarget((target_ip, 161)),  # SNMP agent address and port
                    ContextData(),
                    ObjectType(ObjectIdentity(oid), value)
                )

                # Perform SNMP SET operation
                error_indication, error_status, error_index, var_binds = next(set_command)

                # Check for SNMP SET errors
                if error_indication:
                    result = f"Failed: {error_indication}"
                elif error_status:
                    result = f"Failed: {error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}"
                else:
                    result = f"Successful"

                # Write result to CSV file along with other information
                writer.writerow({'Target_IP': target_ip, 'OID': oid, 'Value': value, 'Result': result})

                print(f"SNMP SET operation for {target_ip} with OID {oid} completed. Result: {result}")

            except FileNotFoundError:
                print(f"One of the required files not found for OID file {oid_file}. Skipping...")
                continue

input("Press Enter to close...")
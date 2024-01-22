data = []
path = str(input("Input data file path:"))

try:
    with open(path, 'r') as file:
        for line in file:
            row = line.strip().split(',')
            data.append(row)
except FileNotFoundError:
    print("File not Found")
    exit(0)

results = {}
answer = []
for row in data:
    ip_address_tr = row[0]
    ip_address_re = row[1]
    transmitted_bytes = int(row[5])
    transmitted_packets = int(row[4])
    if not ip_address_tr in results:
        results[f"{ip_address_tr}"] = {"tp": transmitted_packets, "tb": transmitted_bytes, "rp": 0, "rb": 0}
    else:
        results[f"{ip_address_tr}"]["tp"] += transmitted_packets
        results[f"{ip_address_tr}"]["tb"] += transmitted_bytes
    if not ip_address_re in results:
        results[f"{ip_address_re}"] = {"rp": transmitted_packets, "rb": transmitted_bytes, "tp": 0, "tb": 0}
    else:
        results[f"{ip_address_re}"]["rp"] += transmitted_packets
        results[f"{ip_address_re}"]["rb"] += transmitted_bytes
for result in results:
    answer.append([result, results[result]["rp"], results[result]["rb"], results[result]["tp"], results[result]["tb"]])

with open('output.csv', 'w') as file:
    for row in answer:
        file.write(','.join(str(x) for x in row) + '\n')

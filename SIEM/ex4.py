with open('test.log', 'r') as file:
    failed_lines = []
    for line in file:
        print(line)
        if "Failed" in line:
            failed_lines.append(line)
print()
print()

for fail_line in failed_lines:
    print(fail_line)

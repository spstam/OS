# This Python code will generate a string of 4096 'A's.
character = 'A'
size_in_bytes = 4096
string_4kb = character * size_in_bytes


# You can then print it or save it to a file.
# To print (it will be very long):
# print(string_4kb)

# To save it directly to a new file named '4kb_data.txt':
with open('12kb_data.txt', 'w') as f:
    f.write(string_4kb)
print(f"A string of {size_in_bytes} characters has been saved to 4kb_data.txt")

# If you want to copy the string to your clipboard to paste elsewhere,
# for smaller sizes you could print and copy, but for 4KB,
# it's often easier to generate it where you need it or save it to a file first.

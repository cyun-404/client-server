import random

p = input("Enter p:")
g = input("Enter g:")
a = random.randint(1, 100)      # syntax reference: https://docs.python.org/3/library/random.html
b = random.randint(1, 100)
A = ((pow(g, a)) % p)           # syntax reference: https://www.geeksforgeeks.org/pow-in-python/
B = ((pow(g, b)) % p)
Ka = ((pow(B, a)) % p)
Kb = ((pow(A, b)) % p)
print("Secret key at A = ", str(Ka))
print("Secret key at B = ", str(Kb))

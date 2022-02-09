// HACK: To properly view the text if your screen is too small to fit the entire string, press ALT + z

// ----------HASH----------

// The word "hash" has culinary roots: it refers to chopping and mixing, which accurately describes what happens in a hashing function.
// You give it an input that can be of any length, and it will output a fixed length value.
// The important thing to understand is that the function will always produce the same output given the same input. This is useful to store data without knowing its true value.

// EXAMPLE: storing a password in a database.You don't want to store the real password in a database, because if a hacker gets a hold of that database the passwords would be stolen. If the data is hashed, they would have to also crack that hash to have the passwords.

const { createHash } = require("crypto"); //crypto is a Node built in module

// Create a string hash
// This function takes a string as input and gives back a hash string as output
function hash(str) {
  return createHash("sha256").update(str).digest("hex");
}
// .createHash(insert hashing algorithm here) This creates the hash. sha256 stands for "secure hash algorithm" and returns a hash value, also called a 256-bit "digest"
//.update(what you want to be hashed)
//.digest(the format you want to return. Example: 'hex' or 'base64') This returns the output

// hex: (hexadecimal numeral system) is a positional numeral system that represents numbers using a radix (base) of 16 Unlike the decimal system representing numbers using 10 symbols (0 to 9), hexadecimal uses 16 distinct symbols(0 to 9 and A to F)

// Let's pass an input to our hashing function and see it in action!
let password1 = "mySuperSecretPasswordDefinitelyNot123";
const hash1 = hash(password1);
console.log(hash1);

// Compare the two hashed passwords and check if they're the same
const password2 = "mySuperSecretPasswordDefinitelyNot123";
const hash2 = hash(password2);
const match = hash1 === hash2;

console.log(match ? "It's a match 🔥" : "Not a match ❌");

// ----------SALT----------

//Since hashes always produce the same output, it's not very secure by itself. That's why we add salt. A salt is a random string added to the input before the hashing.

const { scryptSync, randomBytes, timingSafeEqual } = require("crypto");

const users = [];

function signup(email, password) {
  const salt = randomBytes(16).toString("hex"); //create a random set of characters
  const hashedPassword = scryptSync(password, salt, 64).toString("hex"); // Now we hash it. We provide the original password and salt, plus a key length (recommended to be 64). The scryptSync() is an inbuilt function which Provides a synchronous scrypt implementation in Node. scrypt is a password-based key derivation function that is designed to be expensive computationally and memory-wise in order to make brute-force attacks unrewarding.
  const user = {
    email,
    password: `${salt}:${hashedPassword}`, // Now that we have a hashed password we need to also store the salt with it, and we can do that by pre-pending it to the existing string separated by a semi-colon.
  };

  users.push(user);

  return user;
}

function login(email, password) {
  const user = users.find((theUser) => theUser.email === email);

  const [salt, key] = user.password.split(":"); // When the user logs in, we can grab the salt from the database and recreate the original hash.
  const hashedBuffer = scryptSync(password, salt, 64);

  const keyBuffer = Buffer.from(key, "hex"); //The Buffer class in Node.js is designed to handle raw binary data. Each buffer corresponds to some raw memory allocated outside V8. Buffers act somewhat like arrays of integers, but aren't resizable and have a whole bunch of methods specifically for binary data. The integers in a buffer each represent a byte and so are limited to values from 0 to 255 inclusive. When using console.log() to print the Buffer instance, you'll get a chain of values in hexadecimal values.

  const match = timingSafeEqual(hashedBuffer, keyBuffer); // Instead of just comparing the strings here, we add an extra security layer by using the timingSafeEqual function which can prevent timing attacks. This function is based on a constant-time algorithm. Returns true if a is equal to b, without leaking timing information that would allow an attacker to guess one of the values.

  if (match) {
    return "login successful";
  } else {
    return "login failed";
  }
}

const user = signup("john@doe.com", "LePassword");
console.log(user);

const result = login("john@doe.com", "notLePassword");
console.log(result);

// https://fireship.io/lessons/node-crypto-examples/

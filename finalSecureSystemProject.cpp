#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <random>
#include <cstring>
#include <algorithm>

using namespace std;

// ==========================================
// MODULE 1: ADVANCED ENCRYPTOR (CORE UTILS)
// ==========================================
namespace util
{
  static inline uint64_t splitmix64(uint64_t x)
  {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
  }

  uint64_t seed_from_password_nonce(const string &password, uint64_t nonce)
  {
    const uint64_t FNV_OFFSET = 1469598103934665603ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    uint64_t h = FNV_OFFSET;
    for (unsigned char c : password)
    {
      h ^= c;
      h *= FNV_PRIME;
    }
    return splitmix64(h ^ splitmix64(nonce));
  }

  void fill_keystream(mt19937_64 &prng, vector<unsigned char> &ks)
  {
    size_t i = 0, n = ks.size();
    while (i < n)
    {
      uint64_t r = prng();
      size_t take = min<size_t>(8, n - i);
      memcpy(&ks[i], &r, take);
      i += take;
    }
  }
}

static const char MAGIC[8] = {'E', 'N', 'C', 'I', 'M', 'G', 'O', '1'};

// Run File Encryptor/Decryptor Inside Menu
void runFileEncryptor()
{
  int modeChoice;
  string inFile, outFile, password;

  cout << "\n---  Advanced File Security Tool ---" << endl;
  cout << "1. Encrypt a File (Lock)" << endl;
  cout << "2. Decrypt a File (Unlock)" << endl;
  cout << "Enter choice: ";
  cin >> modeChoice;
  cin.ignore();

  if (modeChoice != 1 && modeChoice != 2)
  {
    cout << " Invalid Mode Choice." << endl;
    return;
  }

  cout << "Enter Input File Path (e.g. file2.txt): ";
  getline(cin, inFile);
  cout << "Enter Output File Path (e.g. file2.enc): ";
  getline(cin, outFile);
  cout << "Enter Password: ";
  getline(cin, password);

  constexpr size_t CHUNK = 1 << 20; // 1MB
  vector<unsigned char> inbuf(CHUNK), ks(CHUNK);

  if (modeChoice == 1) // ENCRYPT
  {
    ifstream fin(inFile, ios::binary);
    if (!fin)
    {
      cerr << " Cannot open input: " << inFile << "\n";
      return;
    }

    fin.seekg(0, ios::end);
    if (fin.tellg() <= 0)
    {
      cerr << " Input file is empty.\n";
      return;
    }
    fin.seekg(0, ios::beg);

    ofstream fout(outFile, ios::binary);
    if (!fout)
    {
      cerr << " Cannot open output: " << outFile << "\n";
      return;
    }

    uint64_t nonce;
    {
      random_device rd;
      nonce = (static_cast<uint64_t>(rd()) << 32) ^ rd();
    }

    fout.write(MAGIC, 8);
    fout.write(reinterpret_cast<const char *>(&nonce), sizeof(nonce));

    uint64_t seed = util::seed_from_password_nonce(password, nonce);
    mt19937_64 prng(seed);

    while (true)
    {
      fin.read(reinterpret_cast<char *>(inbuf.data()), inbuf.size());
      streamsize got = fin.gcount();
      if (got <= 0)
        break;
      ks.resize(static_cast<size_t>(got));
      util::fill_keystream(prng, ks);
      for (size_t i = 0; i < static_cast<size_t>(got); ++i)
        inbuf[i] ^= ks[i];
      fout.write(reinterpret_cast<const char *>(inbuf.data()), got);
    }
    cout << " Successfully Encrypted '" << inFile << "' -> '" << outFile << "'\n";
  }
  else // DECRYPT
  {
    ifstream fin(inFile, ios::binary);
    if (!fin)
    {
      cerr << " Cannot open input: " << inFile << "\n";
      return;
    }

    fin.seekg(0, ios::end);
    if (fin.tellg() <= 0)
    {
      cerr << " Input file is empty.\n";
      return;
    }
    fin.seekg(0, ios::beg);

    ofstream fout(outFile, ios::binary);
    if (!fout)
    {
      cerr << " Cannot open output: " << outFile << "\n";
      return;
    }

    char magic[8];
    uint64_t nonce = 0;

    fin.read(magic, sizeof(magic));
    if (!fin || !equal(begin(MAGIC), end(MAGIC), magic))
    {
      cerr << " Bad Header: Input file is not encrypted with this system.\n";
      return;
    }

    fin.read(reinterpret_cast<char *>(&nonce), sizeof(nonce));
    if (!fin)
    {
      cerr << " Failed to read cryptographic nonce.\n";
      return;
    }

    uint64_t seed = util::seed_from_password_nonce(password, nonce);
    mt19937_64 prng(seed);

    while (true)
    {
      fin.read(reinterpret_cast<char *>(inbuf.data()), inbuf.size());
      streamsize got = fin.gcount();
      if (got <= 0)
        break;
      ks.resize(static_cast<size_t>(got));
      util::fill_keystream(prng, ks);
      for (size_t i = 0; i < static_cast<size_t>(got); ++i)
        inbuf[i] ^= ks[i];
      fout.write(reinterpret_cast<const char *>(inbuf.data()), got);
    }
    cout << " Successfully Decrypted '" << inFile << "' -> '" << outFile << "'\n";
  }
}

// ==========================================
// MODULE 2: SECURE CHAT APPLICATION
// ==========================================
string caesarEncrypt(string text, int key = 3)
{
  string result = "";
  for (char c : text)
  {
    if (isalpha(c))
    {
      char base = islower(c) ? 'a' : 'A';
      result += char((c - base + key) % 26 + base);
    }
    else
    {
      result += c;
    }
  }
  return result;
}

string caesarDecrypt(string text, int key = 3)
{
  return caesarEncrypt(text, 26 - key);
}

void runChatSession()
{
  string user1, user2, message;
  int choice;

  cout << "\n---  Secure Chat Simulator ---" << endl;
  cout << "Enter name of User 1: ";
  cin >> user1;
  cout << "Enter name of User 2: ";
  cin >> user2;

  do
  {
    cout << "\n1. " << user1 << " sends message\n";
    cout << "2. " << user2 << " sends message\n";
    cout << "3. Exit Chat Room\n";
    cout << "Enter choice: ";
    cin >> choice;
    cin.ignore();

    switch (choice)
    {
    case 1:
      cout << user1 << " > ";
      getline(cin, message);
      cout << "[Network Layer Transmitting: " << caesarEncrypt(message) << "]\n";
      cout << user2 << " received: " << caesarDecrypt(caesarEncrypt(message)) << "\n";
      break;
    case 2:
      cout << user2 << " > ";
      getline(cin, message);
      cout << "[Network Layer Transmitting: " << caesarEncrypt(message) << "]\n";
      cout << user1 << " received: " << caesarDecrypt(caesarEncrypt(message)) << "\n";
      break;
    case 3:
      cout << " Chat session ended.\n";
      break;
    default:
      cout << " Invalid choice.\n";
    }
  } while (choice != 3);
}

// ==========================================
// MODULE 3: USER AUTHENTICATION & HUB MENU
// ==========================================
void registerUser()
{
  string username, password, age;
  cout << "\n---  Register Account ---\n";
  cout << "Enter username: ";
  cin >> username;
  cout << "Enter password: ";
  cin >> password;
  cout << "Enter age: ";
  cin >> age;

  ofstream file("file.txt", ios::app);
  if (file.is_open())
  {
    file << username << " " << password << " " << age << "\n";
    file.close();
    cout << " Registration successful!\n";
  }
  else
  {
    cout << " Error opening verification file.\n";
  }
}

// Global Dashboard Menu after login
void showDashboard(string loggedInUser, string age)
{
  int choice;
  do
  {
    cout << "\n====================================" << endl;
    cout << "    SECURE APPS DASHBOARD         " << endl;
    cout << "   Logged In: " << loggedInUser << " (Age: " << age << ")" << endl;
    cout << "====================================" << endl;
    cout << "1. Open Secure Chat Simulator " << endl;
    cout << "2. Open Advanced File Locker " << endl;
    cout << "3. Logout and Return to Main Menu " << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    switch (choice)
    {
    case 1:
      runChatSession();
      break;
    case 2:
      runFileEncryptor();
      break;
    case 3:
      cout << " Logged out successfully.\n";
      break;
    default:
      cout << " Invalid input. Try again.\n";
    }
  } while (choice != 3);
}

void loginUser()
{
  string username, password;
  string line, storedUser, storedPass, storedAge;
  bool success = false;

  cout << "\n---  Security Portal Login ---\n";
  cout << "Enter username: ";
  cin >> username;
  cout << "Enter password: ";
  cin >> password;

  ifstream file("file.txt");
  if (!file.is_open())
  {
    cout << " System Database Error: No registered users found yet.\n";
    return;
  }

  while (getline(file, line))
  {
    istringstream iss(line);
    iss >> storedUser >> storedPass >> storedAge;
    if (username == storedUser && password == storedPass)
    {
      success = true;
      break;
    }
  }
  file.close();

  if (success)
  {
    cout << " Login successful!\n";
    showDashboard(storedUser, storedAge);
  }
  else
  {
    cout << " Login failed: Incorrect username or password.\n";
  }
}

void changePassword()
{
  string username, oldPass, newPass1, newPass2;
  string line, storedUser, storedPass, storedAge;
  string lines[1000];
  int count = 0;
  bool found = false;
  bool passwordChanged = false;

  cout << "\n---  Change Account Password ---\n";
  cout << "Enter username: ";
  cin >> username;
  cout << "Enter old password: ";
  cin >> oldPass;

  ifstream file("file.txt");
  if (!file.is_open())
  {
    cout << " Database file not found.\n";
    return;
  }

  while (getline(file, line))
  {
    istringstream iss(line);
    iss >> storedUser >> storedPass >> storedAge;

    if (storedUser == username && storedPass == oldPass)
    {
      found = true;
      cout << "Enter new password: ";
      cin >> newPass1;
      cout << "Confirm new password: ";
      cin >> newPass2;

      if (newPass1 == newPass2)
      {
        lines[count++] = storedUser + " " + newPass1 + " " + storedAge;
        passwordChanged = true;
      }
      else
      {
        lines[count++] = storedUser + " " + storedPass + " " + storedAge;
        cout << " New passwords do not match.\n";
      }
    }
    else
    {
      lines[count++] = storedUser + " " + storedPass + " " + storedAge;
    }
  }
  file.close();
  if (!found)
  {
    cout << " Authentication failed: Incorrect details.\n";
    return;
  }
  ofstream outFile("file.txt");
  for (int i = 0; i < count; ++i)
  {
    outFile << lines[i] << "\n";
  }
  outFile.close();
  if (passwordChanged)
  {
    cout << " Password updated successfully!\n";
  }
}
// main function
int main()
{
  // 1
  int choice;
  do
  {
    cout << "\n====================================" << endl;
    cout << "    CRYPTOGRAPHIC SUITE HOMEPAGE   " << endl;
    cout << "====================================" << endl;
    cout << "1. Register New User\n";
    cout << "2. Account Login\n";
    cout << "3. Reset/Change Password\n";
    cout << "4. Exit Application\n";
    cout << "Enter your choice: ";
    cin >> choice;
    switch (choice)
    {
    case 1:
      registerUser();
      break;
    case 2:
      loginUser();
      break;
    case 3:
      changePassword();
      break;
    case 4:
      cout << " Exiting Suite. Security Session Cleared.\n";
      break;
    default:
      cout << " Invalid selection. Try again.\n";
    }
  } while (choice != 4);
  return 0;
}

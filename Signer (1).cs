using EimzoWrapper;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Crmf;
using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace Library
{
    /// <summary>
    /// Класс подписания по выбранному алгоритму.
    /// </summary>
    public static class Signer
    {
        private static string thumbprint;
        private static string keyId;
        private static int statusCode;
        private static DateTime keyIdCreate;
        private static string certLinuxPath;
        private static string extension = "*.cer";
        private static string delimiter;


        /// <summary>
        /// Подписать данные.
        /// </summary>
        /// <param name="certificateThumbprint">Отпечаток сертификата.</param>
        /// <param name="signingData">Подписываемые данные закодированные в формате base64.</param>
        /// <param name="result">Подписанные данные закодированные в формате base64, либо текст сообщения об ошибке.</param>
        public static int SignData(string certificateThumbprint, string signingData, out string result)
        {
            statusCode = 0;
            var data = Convert.FromBase64String(signingData);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                certLinuxPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "/DSKEYS/";
                delimiter = "\",\"";
            }
            else
            {
                certLinuxPath = string.Empty;
                delimiter = "\\\",\"";
            }

            var thumbprintNew = certificateThumbprint;

            var response = GenerateResponse(data, thumbprintNew);

            result = response;
            return statusCode;
        }

        private static string GenerateResponse(byte[] data, string thumbprintNew)
        {
            string signature = String.Empty;

            X509Certificate2 certificate;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) certificate = GetCertificateFromPath(thumbprintNew, certLinuxPath);
            else certificate = GetCertificateFromStore(thumbprintNew);
            if (certificate == null)
            {
                statusCode = (int)SignDataResult.NotFound;
                return Localizer.L("ERR_CERTIFICATE_NOT_FOUND");
            }

            if (thumbprint != thumbprintNew || String.IsNullOrEmpty(keyId))
            {
                thumbprint = thumbprintNew;
                keyId = GetKeyId(certificate);
            }

            if (keyId != null && IsOlderThanThirtyMinutes())
            {
                keyId = GetKeyId(certificate);
            }

            if (keyId == null)
            {
                statusCode = (int)SignDataResult.NotFound;
                return Localizer.L("ERR_CERTIFICATE_NOT_FOUND");
            }

            var encodedData = Encoding.UTF8.GetString(data);

            //Проверка, Нужно ли подписать сам документ или его хэш
            //Если да, то воспользоваться append_pkcs7_attached и attach_timestamp_token_pkcs7
            //Если нет, то подписать с помощью create_pkcs7
            if (encodedData.Contains("forsign")) signature = MultibankSign(encodedData, certificate);
            else signature = DirectumRawSignature(data, certificate);
            return signature;
        }

        private static string GetKeyId(X509Certificate2 certificate)
        {
            var response = Sender.SendToEimzo("{\"plugin\":\"pfx\",\"name\":\"list_all_certificates\"}");
            if (response == null)
                return null;

            var cn = certificate.Subject
              .Split(',')
              .Select(s => s.Trim().Replace(" = ", "=").ToLower())
              .Single(s => s.StartsWith("cn="));

            var friendlyName = certificate.FriendlyName;

            var certificates = response.SelectToken("certificates");
            foreach (var cert in certificates)
            {
                var alias = cert["alias"].ToString();
                if (!alias.Contains(cn) || !alias.Contains(friendlyName))
                    continue;

                var arguments = "{\"plugin\":\"pfx\",\"name\":\"load_key\",\"arguments\":[\"" +
                                cert["disk"] + delimiter +
                                cert["path"] + "\",\"" +
                                cert["name"] + "\",\"" +
                                cert["alias"] + "\"]}";
                response = Sender.SendToEimzo(arguments);
                if (response == null)
                    return null;

                keyId = response.Value<string>("keyId");
                break;
            }


            if (string.IsNullOrEmpty(keyId))
                return null;

            keyId = response.Value<string>("keyId");

            keyIdCreate = DateTime.Now;

            return keyId;
        }

        internal static string MultibankSign(string encodedData, X509Certificate2 certificate)
        {
            string parametrDRX = encodedData.Substring(encodedData.IndexOf("forsign"));
            string param = parametrDRX.Substring(parametrDRX.IndexOf("{"));

            int lastIndex;
            List<int> indexes = new List<int>();
            if (param.Contains("\"}")) indexes.Add(param.LastIndexOf("\"}") + 2);
            if (param.Contains("}}")) indexes.Add(param.LastIndexOf("}}") + 2);
            if (param.Contains("]}")) indexes.Add(param.LastIndexOf("]}") + 2);
            indexes.Sort();
            lastIndex = indexes.Last();
            if (param.Contains("\"}")) param = param.Substring(0, lastIndex); //Проверка в связи с тем, что данные подписания помещаются внутрь данных о сертификате подписующего

            JObject json = JObject.Parse(param);
            string address = json.SelectToken("address").ToString();
            string login = json.SelectToken("login").ToString();
            string password = json.SelectToken("password").ToString();
            int document_id = json.Value<int>("document_id");
            bool issigned = json.Value<bool>("issigned");
            string pkcs7 = json.SelectToken("pkcs7").ToString();
            if (!issigned) pkcs7 = Convert.ToBase64String(Encoding.UTF8.GetBytes(pkcs7));

            string signature_hex = String.Empty;
            string sign = String.Empty;
            JObject response = new JObject();

            response = CreateOrAttachPKCS7(pkcs7, issigned).Result;
            if (!response.Value<bool>("success"))
                if (response.Value<string>("reason") == "Ключ по идентификатору не найден")
                {
                    GetKeyId(certificate);
                    response = CreateOrAttachPKCS7(pkcs7, issigned).Result;
                }

            sign = response.Value<string>("pkcs7_64");
            signature_hex = response.Value<string>("signature_hex");

            #region получание timestamp

            string timestampstring = "";
            try
            {
                var client = new RestClient("https://api-staging.multibank.uz/api/references/v1/timestamp");
                RestRequest request = new RestRequest("", Method.Get);
                request.AddParameter("signature_hex", signature_hex);
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                RestResponse respons = client.Execute(request);
                timestampstring = JObject.Parse(respons.Content).SelectToken("data").ToString();
            }
            catch (Exception ex) 
            {
                Console.WriteLine(ex);
            }

            //Прикрепление timestamp к pkcs7
            response = Sender.SendToEimzo("{\"plugin\": \"pkcs7\",\"name\": \"attach_timestamp_token_pkcs7\"," +
                                "\"arguments\": [\"" + sign + "\",\"" + certificate.SerialNumber + "\",\"" + timestampstring + "\"]}");
            string attachedString = response.SelectToken("pkcs7_64").ToString();
            #endregion

            ReturnToDirectum(address, login, password, document_id, attachedString);

            return signature_hex;
        }

        internal static async Task<JObject> CreateOrAttachPKCS7(string data, bool isSigned, bool detached_body = false)
        {
            var detached_body_argument = "no";
            if (detached_body == true) detached_body_argument = "yes";
            string arg = String.Empty;
            if (isSigned) arg = "{\"plugin\": \"pkcs7\",\"name\": \"append_pkcs7_attached\",\"arguments\": [\"" + data + "\",\"" + keyId + "\"]}";
            else arg = "{\"plugin\": \"pkcs7\",\"name\": \"create_pkcs7\",\"arguments\": [\"" + data + "\",\"" + keyId + "\",\"" + detached_body_argument+ "\"]}";
            var response = await Task.Run(() => Sender.SendToEimzo(arg));
            return response;
        }

        //Для интеграции с Мультибанк
        public static void ReturnToDirectum(string address, string login, string password, int document_id, string sign)
        {
            #region Отправка обратно в DirectumRX
            string serveraddress = address + "integration/odata/MultibankModule";
            string parametr = @"{""externalSign"": ""{body}"", ""document_id"": {id}}";

            parametr = parametr.Replace("{body}", sign).Replace("{id}", document_id.ToString());
            JObject jObject = JObject.Parse(parametr);
            var client = new RestClient(serveraddress);
            var request = new RestRequest("ImportSign/", Method.Post);
            request.AddHeader("Authorization", String.Format("Basic {0}", Convert.ToBase64String(Encoding.Default.GetBytes(login + ":" + password))));
            request.AddJsonBody(parametr);
            
            var resp = client.Execute(request);

            #endregion
        }

        internal static string DirectumRawSignature(byte[] data, X509Certificate2 certificate)
        {
            string base64data = Convert.ToBase64String(data);
            var response = CreateOrAttachPKCS7(base64data, false).Result;
            var responseString = response.ToString();
            // Проверяем, что длина строки больше 1000 символов
            if (responseString.Length > 1000)
            {
                string truncatedResponse = responseString.Substring(0, 1000);
            }
            if (!response.Value<bool>("success"))
            {
                if (response.Value<string>("reason") == "Ключ по идентификатору не найден")
                {
                    GetKeyId(certificate);
                    response = CreateOrAttachPKCS7(base64data, false, true).Result;
                }
            }

            return response.Value<string>("pkcs7_64");
        }

        /// <summary>
        /// Hex строку в byteArray
        /// </summary>
        /// <param name="inputHex"></param>
        /// <returns></returns>
        public static byte[] HexStringToHex(string inputHex)
        {
            var resultantArray = new byte[inputHex.Length / 2];
            for (var i = 0; i < resultantArray.Length; i++)
            {
                resultantArray[i] = System.Convert.ToByte(inputHex.Substring(i * 2, 2), 16);
            }
            return resultantArray;
        }

        /// <summary>
        /// Получить сертификат с закрытым ключом из хранилища текущего пользователя.
        /// </summary>
        /// <param name="thumbprint">Отпечаток сертификата.</param>
        /// <returns>Сертификат.</returns>
        private static X509Certificate2 GetCertificateFromStore(string thumbprint)
        {
            var store = new X509Store();
            store.Open(OpenFlags.ReadOnly);
            var privateKeyCertificate = store.Certificates
              .OfType<X509Certificate2>()
              .FirstOrDefault(c => (c.Thumbprint?.Equals(thumbprint, StringComparison.OrdinalIgnoreCase) ?? false) && c.HasPrivateKey);
            store.Close();
            return privateKeyCertificate;
        }

        /// <summary>
        /// Получить сертификат с закрытым ключом из директории.
        /// </summary>
        /// <param name="thumbprint">Отпечаток сертификата.</param>
        /// <returns>Сертификат.</returns>
        private static X509Certificate2 GetCertificateFromPath(string thumbprint, string path)
        {
            List<X509Certificate2> certs = new List<X509Certificate2>();
            int i = 0;
            foreach (string cert in GetFiles(path, extension))
            {
                i++;
                X509Certificate2 x509cert2 = new X509Certificate2(cert);
                certs.Add(x509cert2);
            }
            return certs.OfType<X509Certificate2>()
              .FirstOrDefault(c => c.Thumbprint == thumbprint);
        }

        public static IEnumerable<string> GetFiles(string root, string spec)
        {
            var pending = new Stack<string>(new[] { root });

            while (pending.Count > 0)
            {
                var path = pending.Pop();
                IEnumerator<string> fileIterator = null;

                try
                {
                    fileIterator = Directory.EnumerateFiles(path, spec).GetEnumerator();
                }

                catch { }

                if (fileIterator != null)
                {
                    using (fileIterator)
                    {
                        while (true)
                        {
                            try
                            {
                                if (!fileIterator.MoveNext()) // Throws if file is not accessible.
                                    break;
                            }

                            catch { break; }

                            yield return fileIterator.Current;
                        }
                    }
                }

                IEnumerator<string> dirIterator = null;

                try
                {
                    dirIterator = Directory.EnumerateDirectories(path).GetEnumerator();
                }

                catch { }

                if (dirIterator != null)
                {
                    using (dirIterator)
                    {
                        while (true)
                        {
                            try
                            {
                                if (!dirIterator.MoveNext()) // Throws if directory is not accessible.
                                    break;
                            }

                            catch { break; }

                            pending.Push(dirIterator.Current);
                        }
                    }
                }
            }
        }

        public static bool IsOlderThanThirtyMinutes()
        {
            DateTime currentTimestamp = DateTime.Now;
            TimeSpan timeDifference = currentTimestamp - keyIdCreate;
            return timeDifference.TotalMinutes > 30;
        }
    }
}

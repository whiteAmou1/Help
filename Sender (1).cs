using System;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Ninja.WebSockets;

namespace EimzoWrapper
{
    public static class Sender
    {
        private const int BufferSize = 8192;

        private static bool initialized;

        private static readonly WebSocketClientFactory webSocketClientFactory = new WebSocketClientFactory();

        private static void Init()
        {
            if (initialized)
                return;

            initialized = true;
            SendToEimzo("{\"name\": \"apikey\"," +
                        "\"arguments\": [\"127.0.0.1\"," +
                        "\"A7BCFA5D490B351BE0754130DF03A068F855DB4333D43921125B9CF2670EF6A40370C646B90401955E1F7BC9CDBF59CE0B2C5467D820BE189C845D0B79CFC96F\"]}");
        }
        private static string SendToWebSocket(WebSocket ws, string data)
        {
            var bytesToSend = Encoding.UTF8.GetBytes(data);
            var chunks = bytesToSend.Length / BufferSize;
            for (int i = 0; i <= chunks; i++)
            {
                var chunkLen = Math.Min(BufferSize, bytesToSend.Length - i * BufferSize);
                var chunkArray = new byte[chunkLen];
                var chunk = new ArraySegment<byte>(chunkArray);
                Array.Copy(bytesToSend, i * BufferSize, chunkArray, 0, chunkLen);
                ws.SendAsync(chunk, WebSocketMessageType.Text, i == chunks, CancellationToken.None).Wait();
            }

            var bufferArray = new byte[BufferSize];
            var buffer = new ArraySegment<byte>(bufferArray);
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    var resp = ws.ReceiveAsync(buffer, CancellationToken.None).Result;
                    ms.Write(buffer.Array, 0, resp.Count);
                    if (resp.EndOfMessage)
                        break;
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        public static JObject SendToEimzo(string incomingData)
        {
            try
            {
                Init();

                using (var webSocket = webSocketClientFactory.ConnectAsync(new Uri("ws://127.0.0.1:64646/service/cryptapi")).Result)
                {
                    var result = SendToWebSocket(webSocket, incomingData);
                    webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None).Wait();
                    var jsonResult = (JObject)JsonConvert.DeserializeObject(result);
                    return jsonResult;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }
    }
}

const Sender = (() => {
  const BufferSize = 8192;
  let initialized = false;

  const init = () => {
      if (initialized) return;
      initialized = true;
      const msg = JSON.stringify({
          name: "apikey",
          arguments: ["127.0.0.1", "KEY"]
      });
      sendToEimzo(msg);
  };

  const sendToWebSocket = async (ws, data) => {
      const bytesToSend = new TextEncoder().encode(data);
      const chunks = Math.ceil(bytesToSend.length / BufferSize);

      for (let i = 0; i < chunks; i++) {
          const chunkLen = Math.min(BufferSize, bytesToSend.length - i * BufferSize);
          const chunkArray = bytesToSend.slice(i * BufferSize, i * BufferSize + chunkLen);

          try {
              ws.send(chunkArray);
              console.log(`Chunk ${i + 1}/${chunks} sent successfully`);
          } catch (error) {
              console.error('Error sending chunk:', error);
              return 'Error sending data';
          }
      }

      return 'Data sent successfully';
  };

  const receiveFromWebSocket = async (ws) => {
      let receivedData = [];

      return new Promise((resolve, reject) => {
          ws.onmessage = (event) => {
              if (event.data instanceof Blob) {
                  const reader = new FileReader();
                  reader.onload = () => {
                      const chunk = new Uint8Array(reader.result);
                      receivedData.push(chunk);

                      if (event.data.size < BufferSize) {
                          resolve(new TextDecoder().decode(new Uint8Array(receivedData.flat())));
                      }
                  };
                  reader.onerror = reject;
                  reader.readAsArrayBuffer(event.data);
              } else {
                  reject('Unexpected message format');
              }
          };

          ws.onerror = (error) => {
              reject(error);
          };
      });
  };

  const sendToEimzo = async (incomingData) => {
      try {
          init();

          const ws = new WebSocket('ws://127.0.0.1:64646/service/cryptapi');

          return new Promise((resolve, reject) => {
              ws.onopen = async () => {
                  try {
                      const result = await sendToWebSocket(ws, incomingData);
                      ws.close(1000, 'Normal Closure'); 
                      resolve(result); 
                  } catch (error) {
                      reject(error);
                  }
              };

              ws.onerror = (error) => {
                  reject(error);
              };

              ws.onclose = () => {
                  console.log('WebSocket connection closed');
              };
          });
      } catch (error) {
          console.error('Error:', error.message);
          return null;
      }
  };

  return {
      init,
      sendToEimzo
  };
})();

export default Sender;

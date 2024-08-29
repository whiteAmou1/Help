// Для работы с криптографией и сертификатами
const crypto = require('crypto');

// Для работы с JSON
const { parse, stringify } = JSON;

// Для работы с HTTP запросами (аналог RestSharp)
const axios = require('axios');

// Для работы с файловой системой
const fs = require('fs');
const path = require('path');
const { X509Certificate } = require('crypto'); // Импортируем класс X509Certificate для работы с сертификатами

// Класс для работы с подписью данных
class MultibankSigner {
    constructor() {
        this.keyId = '';
        this.keyIdCreate = null;
    }

    /**
     * Подписывает данные, добавляет временную метку и возвращает результат.
     * @param {string} encodedData - Данные в формате base64 для подписания.
     * @param {X509Certificate} certificate - Сертификат X509.
     * @returns {string} Подписанные данные или null в случае ошибки.
     */
    async multibankSign(encodedData, certificate) {
        try {
            // Извлечение параметров из закодированных данных
            let parametrDRX = encodedData.substring(encodedData.indexOf('forsign'));
            let param = parametrDRX.substring(parametrDRX.indexOf('{'));

            // Определение последнего индекса
            let indexes = [];
            if (param.includes('"}}')) indexes.push(param.lastIndexOf('"}}') + 2);
            if (param.includes('}}')) indexes.push(param.lastIndexOf('}}') + 2);
            if (param.includes(']}')) indexes.push(param.lastIndexOf(']}') + 2);

            indexes.sort((a, b) => a - b);
            let lastIndex = indexes[indexes.length - 1];
            if (param.includes('"}}')) {
                param = param.substring(0, lastIndex);
            }

            // Парсинг JSON
            let json = JSON.parse(param);
            let { address, login, password, document_id, issigned, pkcs7 } = json;

            if (!issigned) {
                pkcs7 = Buffer.from(pkcs7, 'utf8').toString('base64');
            }

            let response = await this.createOrAttachPKCS7(pkcs7, issigned);
            if (!response.success && response.reason === 'Ключ по идентификатору не найден') {
                await this.getKeyId(certificate);
                response = await this.createOrAttachPKCS7(pkcs7, issigned);
            }

            let sign = response.pkcs7_64;
            let signatureHex = response.signature_hex;

            let timestampString = await this.getTimestamp(signatureHex);
            let attachedString = await this.attachTimestamp(sign, certificate, timestampString);

            // Возврат результата в Directum
            await this.returnToDirectum(address, login, password, document_id, attachedString);

            return signatureHex;
        } catch (error) {
            console.error('Ошибка при подписывании:', error);
            return null;
        }
    }

    /**
     * Получение временной метки для подписи.
     * @param {string} signatureHex - Подпись в формате hex.
     * @returns {string} Временная метка или пустая строка в случае ошибки.
     */
    async getTimestamp(signatureHex) {
        try {
            const response = await axios.get('https://api-staging.multibank.uz/api/references/v1/timestamp', {
                params: { signature_hex: signatureHex }
            });
            return response.data.data;
        } catch (error) {
            console.error('Ошибка при получении временной метки:', error);
            return '';
        }
    }

    /**
     * Присоединение временной метки к подписанным данным.
     * @param {string} sign - Подписанные данные в формате PKCS7.
     * @param {X509Certificate} certificate - Сертификат X509.
     * @param {string} timestampString - Временная метка.
     * @returns {string} Обновленные подписанные данные или null в случае ошибки.
     */
    async attachTimestamp(sign, certificate, timestampString) {
        try {
            const response = await axios.post('https://eimzo-api-url', {
                plugin: 'pkcs7',
                name: 'attach_timestamp_token_pkcs7',
                arguments: [sign, certificate.serialNumber, timestampString]
            });
            return response.data.pkcs7_64;
        } catch (error) {
            console.error('Ошибка при присоединении временной метки:', error);
            return null;
        }
    }

    /**
     * Создание или присоединение PKCS7 подписи.
     * @param {string} data - Данные для подписи.
     * @param {boolean} isSigned - Флаг, указывающий, подписаны ли данные.
     * @param {boolean} detachedBody - Флаг для использования отсоединенного тела.
     * @returns {Object} Ответ сервера или ошибка.
     */
    async createOrAttachPKCS7(data, isSigned, detachedBody = false) {
        try {
            const detachedBodyArg = detachedBody ? 'yes' : 'no';
            const arg = isSigned
                ? `{"plugin": "pkcs7","name": "append_pkcs7_attached","arguments": ["${data}","${this.keyId}"]}`
                : `{"plugin": "pkcs7","name": "create_pkcs7","arguments": ["${data}","${this.keyId}","${detachedBodyArg}"]}`;

            const response = await axios.post('https://eimzo-api-url', JSON.parse(arg));
            return response.data;
        } catch (error) {
            console.error('Ошибка при создании или присоединении PKCS7:', error);
            return { success: false, reason: 'Ошибка соединения' };
        }
    }

    /**
     * Возврат подписанных данных в систему Directum.
     * @param {string} address - Адрес сервера Directum.
     * @param {string} login - Логин для доступа к Directum.
     * @param {string} password - Пароль для доступа к Directum.
     * @param {string} document_id - Идентификатор документа.
     * @param {string} sign - Подписанные данные.
     */
    async returnToDirectum(address, login, password, document_id, sign) {
        try {
            const serverAddress = `${address}integration/odata/MultibankModule`;
            const params = {
                externalSign: sign,
                document_id: document_id
            };

            await axios.post(`${serverAddress}/ImportSign/`, params, {
                headers: {
                    'Authorization': `Basic ${Buffer.from(`${login}:${password}`).toString('base64')}`
                }
            });
        } catch (error) {
            console.error('Ошибка при возврате в Directum:', error);
        }
    }

    /**
     * Получение идентификатора ключа для подписания.
     * @param {X509Certificate} certificate - Сертификат X509.
     */
    async getKeyId(certificate) {
        // Реализация метода получения ключевого идентификатора.
    }

    /**
     * Проверка, прошло ли более 30 минут с момента создания ключевого идентификатора.
     * @returns {boolean} True, если прошло более 30 минут, иначе False.
     */
    isOlderThanThirtyMinutes() {
        const currentTimestamp = new Date();
        const timeDifference = (currentTimestamp - this.keyIdCreate) / 60000;
        return timeDifference > 30;
    }

    /**
     * Преобразование строки hex в массив байтов.
     * @param {string} inputHex - Строка hex.
     * @returns {Array} Массив байтов.
     */
    static hexStringToByteArray(inputHex) {
        const resultArray = [];
        for (let i = 0; i < inputHex.length; i += 2) {
            resultArray.push(parseInt(inputHex.substr(i, 2), 16));
        }
        return resultArray;
    }

    /**
     * Получение сертификата из хранилища.
     * @param {string} thumbprint - Отпечаток сертификата.
     * @returns {X509Certificate} Сертификат X509.
     */
    static getCertificateFromStore(thumbprint) {
        // Реализация метода получения сертификата из хранилища.
    }

    /**
     * Получение сертификата из директории.
     * @param {string} thumbprint - Отпечаток сертификата.
     * @param {string} path - Путь к директории.
     * @returns {X509Certificate} Сертификат X509.
     */
    static getCertificateFromPath(thumbprint, path) {
        // Реализация метода получения сертификата из директории.
    }

    /**
     * Получение списка файлов с указанным расширением из директории.
     * @param {string} root - Корневая директория.
     * @param {string} spec - Расширение файлов.
     * @returns {Array} Список файлов.
     */
    static getFiles(root, spec) {
        const pending = [root];
        const files = [];

        while (pending.length) {
          const path = pending.pop();
          let fileIterator;

          try {
              fileIterator = fs.readdirSync(path);
          } catch (e) {
              console.error(`Не удалось прочитать директорию ${path}: ${e.message}`);
              continue;
          }

          for (let file of fileIterator) {
              const fullPath = path.join(path, file); // Используем path.join для корректного объединения путей
              const stat = fs.lstatSync(fullPath);

              if (stat.isDirectory()) {
                  pending.push(fullPath);
              } else if (file.endsWith(spec)) {
                  files.push(fullPath);
              }
          }
      }
      return files;
  }
}

/// Пример 
(async () => {
  try {
    const signer = new Signer();
    const encodedData = 'base64encodedDataString'; // Замените на реальный закодированный формат данных
    const certificateThumbprint = 'certificateThumbprint'; // Замените на реальный отпечаток сертификата
    const userLanguage = 'en'; // Замените на реальный язык

    // Подпись данных
    const signedData = signer.signData('pluginName', certificateThumbprint, encodedData, userLanguage);
    console.log('Signed Data:', signedData);

    // Поиск файлов с расширением .cer в директории
    const rootDir = '/path/to/certificates'; // Укажите путь к директории с сертификатами
    const certFiles = Signer.getFiles(rootDir, '.cer');
    console.log('Certificate Files:', certFiles);
} catch (error) {
    console.error('Ошибка при выполнении операций:', error);
}
})();
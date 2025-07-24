#include <iostream>
#include <thread>               // For: std::this_thread::sleep_for()
#include <cstring>              // for memset(), strcpy()
#include <unistd.h>             // For: close()
#include <sys/socket.h>         // For: struct sockaddr
#include <netinet/in.h>         // For: htons(), IPPROTO_ICMP
#include <netinet/ip_icmp.h>    // For ICMP heaader
#include <linux/if_ether.h>     // For: ETH_P_ALL
#include <arpa/inet.h>







// # Штука для безопасного преобразования указателей между собой. То есть мы используем сперва
// # преобразование в void, которое нельзя применить НЕ к указателям. А потом в нужный тип.
template <typename result_t, typename source_t>
result_t pointer_cast(source_t* var)
{
    return static_cast<result_t>(static_cast<void*>(var));
}

// # То же, что и выше, но только константного аргумента
template <typename result_t, typename source_t>
result_t pointer_cast(const source_t* var)
{
    return static_cast<result_t>(static_cast<const void*>(var));
}



//int main()
int main(int argc, const char* argv[])
{
    int         targetPort  {0};
    const char* targetIP    {nullptr};
    int         retValue    {0};

    // # Debug
//    int         argc {2};
//    const char* argv[3] = {"NDNSystems", "192.168.3.2", ""};


    // # Случай, когда пользователь указал некоректное число аргументов
    if (argc != 2) {
        std::cout << "\nUsage: getMAC <target IPv4-address>" << std::endl;
        return 0;
    }
    else {
        targetIP = argv[1];
    }



    // # Инициализация структуры, содержащей адрес цели запроса
    struct sockaddr_in serverSockAddr;
    std::memset(&serverSockAddr, '\0', sizeof(serverSockAddr));

    serverSockAddr.sin_family = AF_INET;              // Коммуникационный домен AF_INET (где адрес = имя хоста + номер порта)
    serverSockAddr.sin_port   = htons(targetPort);    // Номер порта (переведённый в сетевой порядок следования байтов)

    // # Конвертируем IP-адрес из текстовой формы в бинарную (сетевой порядок байт) в нужном
    // # нам исходном формате (так как задан параметр AF_INET, то в формат адресов семейства IPv4)
    retValue = inet_pton(AF_INET, targetIP, &serverSockAddr.sin_addr);
    if (retValue <= 0) {
        std::perror("[ERROR]::[inet_pton]");
        return -1;
    }
    else {}




    // # Создаём сокет для отправки непосредственно echo request по протоколу ICMP.
    // #
    // # AF_INET        - адрес имеет формат хост:порт
    // # SOCK_DGRAM     - передача датаграмм, отдельных пакетов с данными, т.е. порциями
    // # IPPROTO_ICMP   - протокол ICMP
    // #
    int sendSocket {socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)};
    if (sendSocket < 0) {
        std::perror("[ERROR]::[sendSocket]");
        return -1;
    }
    else {
        //std::cout << "\nSocket for the sending of echo request has been created!" << std::endl;
    }



    // # Устанавливаем флаги, связанные с сокетом @sendSocket
    // #
    // # IPPROTO_IP  - установка флага(ов) на уровне работы протокола IP
    // # IP_TTL      - флаг, отвечающий за время жизни пакета
    // #
    int ttlValue {64};
    retValue = setsockopt(sendSocket, IPPROTO_IP,  IP_TTL, (char *)&ttlValue, sizeof(ttlValue));
    if (retValue < 0) {
        std::perror("[ERROR]::[sendSocket]");
        close(sendSocket);
        return -1;
    }
    else {
        //std::cout << "Successfully set TTL for \'sendSock\'!" << std::endl;
    }


    // # Устанавливаем флаги, связанные с сокетом @sendSocket
    // #
    // # SOL_SOCKET     - установка флага(ов) на уровне работы сокета
    // # SO_RCVTIMEO    - флаг, отвечающий за времемя ожидания получения ответного пакета
    // #
    timeval sendSockTimeout {5, 0};
    retValue = setsockopt(sendSocket, SOL_SOCKET,  SO_RCVTIMEO, (char *)&sendSockTimeout, sizeof(sendSockTimeout));
    if (retValue < 0) {
        std::perror("[ERROR]::[sendSocket]");
        close(sendSocket);
        return -1;
    }
    else {
        //std::cout << "Successfully set timeout for \'sendSock\'!" << std::endl;
    }



    // # Теперь создаём ещё один сокет, но уже для получения ответа. Дело в том, что MAC-адреса
    // # нет в ICMP echo reply, то есть этот уровень нам не подходит. Но можно опуститься ниже,
    // # на канальный уровень, где просто обработать входящий пакет ДО того, как он будет обработан
    // # системой и передан на уровень выше (уже без Ethernet-части).
    // #
    // # AF_PACKET          - работа с сырыми сетевыми пакетами
    // # SOCK_RAW           - работа с 'сырыми' датаграммами
    // # htons(ETH_P_ALL)   - работа со всеми протоколами
    int recvSocket {socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))};
    if (recvSocket < 0) {
        std::perror("[ERROR]::[recvSocket]");

        // # Закрываем сокет для отправки ICMP
        close(sendSocket);
        return -1;
    }
    else {
        //std::cout << "\nReceive socket has been created!" << std::endl;
    }



    // # Формируем ICMP пакет для отправки
    icmphdr sendPack;
    std::memset(&sendPack, '\0', sizeof(sendPack));

    sendPack.type = ICMP_ECHO;                      // 0 - echo reply; 8 - echo request
    sendPack.code = 0;                              // Set to 0
    sendPack.checksum = 0;                          // Проверочная сумма
    sendPack.un.echo.id = getpid();                 // Id, чтобы по нему сопоставить между собой echo request и echo reply
    sendPack.un.echo.sequence = 0;                  // Число, служащее для тех же целей, что и id




    // # Отправка пакета
    retValue = sendto(sendSocket, &sendPack, sizeof(sendPack), 0, pointer_cast<const sockaddr*>(&serverSockAddr), sizeof(serverSockAddr));
    if (retValue <= 0) {
        std::perror("[ERROR]::[recvSocket]");

        close(sendSocket);
        close(recvSocket);
        return -1;
    }
    else {
        //std::cout << "Successfully send ping-packet to the \'" << targetIP << '\'' << std::endl;
    }

    // # Ждём некоторое время перед получением ответа
    std::this_thread::sleep_for(std::chrono::seconds(1));




    // # Получаем ответ и парсим заголовок ethernet-кадра
    constexpr int   bufferSize {256};
    char            recvBuffer[bufferSize] = {'\0'};
    socklen_t       addrLen {sizeof(serverSockAddr)};

    retValue = recvfrom(recvSocket, &recvBuffer, bufferSize, 0, pointer_cast<sockaddr*>(&serverSockAddr), &addrLen);
    if (retValue <= 0) {
        std::perror("[ERROR]::[recvSocket]");

        close(sendSocket);
        close(recvSocket);
        return -1;
    }
    else {
        // ## Кастим буффер к типу заголовка ethernet-кадра
        ethhdr *ethFrameHeader = (ethhdr*) recvBuffer;

        std::cout << "Target MAC-address: " << std::hex << std::uppercase
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[0]) << ':'
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[1]) << ':'
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[2]) << ':'
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[3]) << ':'
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[4]) << ':'
                  << static_cast<unsigned int>(ethFrameHeader->h_dest[5]) << std::endl;
    }

    // # Закрываем сокеты
    close(sendSocket);
    close(recvSocket);

    return 0;
}

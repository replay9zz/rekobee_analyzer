# Введение

В этом документе содержится решение вызова HTB «Masks Off».

# Поверхностный анализ

## HTTP GET http://192.168.1.11/ic2kp (4-15)

Специалист использовал известную версию Backdoor:Linux/Rekobee под именем ic2kp.

## HTTP POST http://192.168.1.11:8000/ (701)

Специалист в обратном подключении через HTTP отправил в CNC защищенный архив. Он
таким образом допустил ошибку - привлек внимание. Правильно было бы использовать
команду ic2kp для скачивания файла через зашифрованный трафик.

- Agent: curl
- Filename: b12gb.zip

# Глубокий анализ

## Rekobee

В этом разделе выполнена обратная разработка с целью анализа трафика ic2kp.

Использование: `ic2kp [ -c [ connect_back_host ] ] [ -s secret ] [ -p port ]`.

Общение защищено собственным протоколом поверх TCP:

- CHAP'подобная аутентификация сторон;
- слой AES-HMAC-SHA1 с общим секретом;
- слой XOR на основе последнего пакета. // Ручная реализация AES CBC?

Этот исполняемый файл является клиентом, но создан так, что в него попала одна
неиспользуемая функция инициализации сервера - пасхалка HTB. Невозможно внести
изменения - основная логика CNC отсутствует. Если копией вызвать инициализацию
сервера, то отладка после успешного CHAP невозможна.

Xref:

- https://vms.drweb.ru/virus/?i=7755570
- https://intezer.com/blog/malware-analysis/linux-rekoobe-operating-with-new-undetected-malware-samples/

### Операционирование <a id="operationing"></a>

Основные этапы:

1) подключение;
2) инициализация;
3) ожидание команды;
4) выполнение команды.

Клиент ожидает CNC или самостоятельно подключается к нему (флаг `-c`). Установив
P2P, выполняется инициализация, где стороны проверяют друг друга (CHAP) и задают
вектора инициализации контекстов AES. Клиент получает пакет с номером команды, а
после начинается специфичное ей операционирование.

#### Инициализация

Этот этап возможно рассмотреть с точки зрения обоих сторон за счет пасхалки HTB.

Последовательность:

```
сервер → клиент : начальный пакет
сервер → клиент : пакет с вызовом
клиент → сервер : пакет с вызовом
```

##### Действия сервера

Сервер создает два блока данных:

- `sha1({timeval_1}{pid})`
- `sha1({timeval_2}{pid + 1})`

Они отправляются клиенту в начальном пакете и используются для создания ключей
вида `sha1({секрет}{блок})`. Секрет по умолчанию: `S3cr3tP@ss`. Нет гарантий,
что использовался именно он.

Начальный является единственным пакетом, отправляемым в открытом виде. Далее для
приема и отправки создаются два контекста AES 128, где используется секрет и эти
блоки как векторы инициализации.

Сервер отправляет вызов - статические 16 байт данных. Если клиент отправляет его
же, то аутентификация CHAP успешна.

##### Действия клиента

Клиент получает начальный пакет и оптимизированным компилятором разделяет его на
два вектора инициализации. Создаются два зеркальных контекста AES 128, в которых
используется секрет (флаг `-s`) и эти вектора.

Клиент принимает вызов и сравнивает его со своим, и при совпадении отправляет их
серверу - аутентификация CHAP успешна.

#### Обратное подключение

Последовательность инициализации:

```
сервер → клиент : команда 3
сервер → клиент : значение переменной окружения TERM
сервер → клиент : ((3-й аргумент ioctl))
сервер → клиент : ?
```

Последовательность цикла работы:

```
сервер → клиент : командная строка
клиент → сервер : вывод терминала
```

### Тонкости

#### AES и два по 32 бит избытков

Ключ и вектор инициализации AES 128 задаются при помощи SHA1 160 бит. Как так?

```
13 @ 000013e3  sha1_final(&ctx, &buffer)
14 @ 000013f7  aes_init_key(aes_ctx: aes_ctx, key_ptr: &buffer, key_size: 0x80)
```

Переменная `buffer` является `int128_t`, и после нее имеются другие данные - вот
и ловушка, ведь в процедуре приема защищенных пакетов автор просто перезаписывал
их. Таким образом секрет AES инициализируется 16 байтами из 20 имеющихся, причем
процедурой `sha1_final` они используются как указатель на char.

В итоге ключ AES имеет вид: `sha1({секрет}{блок})[:16]`.

Тоже самое применимо для векторов инициализации, хоть блоки и передаются клиенту
полностью.

### Анализ пакетов

| Этап | Пакет | TSL | Содержание |
|------|-------|-----|------------|
| 2    | 27    | Raw | IV для AES |
|      | 29    | Yes | Вызов CHAP |
|      | 31    |     | Вызов CHAP |
| 3    | 33    |     | ?          |
| 4    | 35... |     | ?          |

> - этапы обозначены в разделе [операционирование](#operationing);
> - TSL обозначает применение слоев защиты AES и XOR, а также HMAC.

### Решение

Достаточно проверить первую сигнатуру - убедиться, что используется правильный
контекст AES. Далее при его помощи расшифровываем все пакеты от сервера, таким
образом _случайно_ находим в этом мессиве пароль от архива. Далее используем
firepwd для получения флага.

Xref:

- https://github.com/lclevy/firepwd

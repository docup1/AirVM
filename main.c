#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

extern char **environ;

// Константы
#define MEM_SIZE 65536         // Размер памяти (64 КБ)
#define STACK_SIZE 1024        // Размер стека
#define NUM_REGS 32            // Количество регистров (R0-R31)
#define MAX_STR_LEN 1024       // Максимальная длина строки

// Коды операций
#define OP_NOP      0x00       // Нет операции
#define OP_HALT     0x01       // Остановка выполнения
#define OP_JUMP     0x02       // Переход
#define OP_CALL     0x03       // Вызов подпрограммы
#define OP_RET      0x04       // Возврат из подпрограммы
#define OP_IF       0x05       // Условный переход
#define OP_LOAD     0x10       // Загрузка из памяти
#define OP_STORE    0x11       // Сохранение в память
#define OP_MOVE     0x12       // Перемещение между регистрами
#define OP_PUSH     0x13       // Поместить в стек
#define OP_POP      0x14       // Извлечь из стека
#define OP_LOADI    0x15       // Загрузка немедленного значения
#define OP_ADD      0x20       // Сложение
#define OP_SUB      0x21       // Вычитание
#define OP_MUL      0x22       // Умножение
#define OP_DIV      0x23       // Деление
#define OP_AND      0x24       // Логическое И
#define OP_OR       0x25       // Логическое ИЛИ
#define OP_XOR      0x26       // Логическое исключающее ИЛИ
#define OP_NOT      0x27       // Логическое НЕ
#define OP_CMP      0x28       // Сравнение
#define OP_FS_LIST  0x34       // Список файлов
#define OP_ENV_LIST 0x42       // Список переменных окружения
#define OP_PRINT    0x50       // Вывод значения (из регистра)
#define OP_INPUT    0x51       // Ввод значения
#define OP_PRINTS   0x52       // Вывод строки из памяти

// Структура виртуальной машины
typedef struct {
    uint8_t memory[MEM_SIZE];      // Память для байт-кода и данных
    uint32_t registers[NUM_REGS];  // Регистры R0-R31
    uint32_t stack[STACK_SIZE];    // Стек
    uint32_t sp;                   // Указатель стека
    uint32_t ip;                   // Указатель инструкций
    uint8_t flags;                 // Флаги: 0x01 - равно, 0x02 - меньше, 0x04 - больше
    int running;                   // Флаг выполнения
    uint32_t program_size;         // Размер загруженного байт-кода
} VM;

// Инициализация виртуальной машины
void vm_init(VM* vm) {
    memset(vm->memory, 0, MEM_SIZE);
    memset(vm->registers, 0, NUM_REGS * sizeof(uint32_t));
    vm->sp = 0;
    vm->ip = 0;
    vm->flags = 0;
    vm->running = 1;
    vm->program_size = 0;
}

// Чтение 4 байт из памяти с автоматическим продвижением указателя инструкций
uint32_t read_uint32(VM* vm) {
    if (vm->ip + 3 >= MEM_SIZE) {
        printf("Error: Cannot read uint32 at offset %u (out of bounds)\n", vm->ip);
        vm->running = 0;
        return 0;
    }
    uint32_t value = (vm->memory[vm->ip] |
                      (vm->memory[vm->ip + 1] << 8) |
                      (vm->memory[vm->ip + 2] << 16) |
                      (vm->memory[vm->ip + 3] << 24));
    vm->ip += 4;
    return value;
}

// Чтение 4 байт из памяти по заданному адресу (без изменения ip)
uint32_t read_uint32_at(VM* vm, uint32_t addr) {
    if (addr + 3 >= MEM_SIZE) {
        printf("Error: Cannot read uint32 at offset %u (out of bounds)\n", addr);
        vm->running = 0;
        return 0;
    }
    return (vm->memory[addr] |
           (vm->memory[addr + 1] << 8) |
           (vm->memory[addr + 2] << 16) |
           (vm->memory[addr + 3] << 24));
}

// Запись 4 байт в память
void write_uint32(VM* vm, uint32_t offset, uint32_t value) {
    if (offset + 3 >= MEM_SIZE) {
        printf("Error: Cannot write uint32 at offset %u (out of bounds)\n", offset);
        vm->running = 0;
        return;
    }
    vm->memory[offset] = value & 0xFF;
    vm->memory[offset + 1] = (value >> 8) & 0xFF;
    vm->memory[offset + 2] = (value >> 16) & 0xFF;
    vm->memory[offset + 3] = (value >> 24) & 0xFF;
}

// Чтение одного байта
uint8_t read_byte(VM* vm) {
    if (vm->ip >= vm->program_size) {
        printf("Error: Read out of bounds\n");
        vm->running = 0;
        return 0;
    }
    return vm->memory[vm->ip++];
}

// Вывод списка файлов
void fs_list(VM* vm, uint32_t dest_addr) {
    char buffer[MAX_STR_LEN] = {0};
    DIR *dir = opendir(".");
    if (!dir) {
        snprintf(buffer, MAX_STR_LEN, "Error: %s", strerror(errno));
    } else {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            strncat(buffer, entry->d_name, MAX_STR_LEN - strlen(buffer) - 2);
            strcat(buffer, "\n");
        }
        closedir(dir);
    }
    size_t len = strlen(buffer);
    if (dest_addr + len + 1 > MEM_SIZE) {
        printf("Error: FS_LIST overflow\n");
        vm->running = 0;
        return;
    }
    memcpy(&vm->memory[dest_addr], buffer, len + 1);
}

// Вывод списка переменных окружения
void env_list(VM* vm, uint32_t dest_addr) {
    char buffer[MAX_STR_LEN] = {0};
    for (char **env = environ; *env; env++) {
        strncat(buffer, *env, MAX_STR_LEN - strlen(buffer) - 2);
        strcat(buffer, "\n");
    }
    size_t len = strlen(buffer);
    if (dest_addr + len + 1 > MEM_SIZE) {
        printf("Error: ENV_LIST overflow\n");
        vm->running = 0;
        return;
    }
    memcpy(&vm->memory[dest_addr], buffer, len + 1);
}

// Основной цикл выполнения программы
void vm_run(VM* vm) {
    while (vm->running) {
        if (vm->ip >= vm->program_size) break;

        uint8_t opcode = read_byte(vm);
        switch (opcode) {
            case OP_NOP:
                break;

            case OP_HALT:
                vm->running = 0;
                break;

            case OP_JUMP: {
                uint32_t addr = read_uint32(vm);
                vm->ip = addr;
                break;
            }

            case OP_CALL: {
                uint32_t addr = read_uint32(vm);
                if (vm->sp >= STACK_SIZE) {
                    printf("Error: Stack overflow\n");
                    vm->running = 0;
                    break;
                }
                vm->stack[vm->sp++] = vm->ip;
                vm->ip = addr;
                break;
            }

            case OP_RET:
                if (vm->sp == 0) {
                    printf("Error: Stack underflow\n");
                    vm->running = 0;
                    break;
                }
                vm->ip = vm->stack[--vm->sp];
                break;

            case OP_IF: {
                uint8_t flag_mask = read_byte(vm);
                uint32_t addr = read_uint32(vm);
                if (vm->flags & flag_mask)
                    vm->ip = addr;
                break;
            }

            case OP_LOAD: {
                // Загрузка значения из памяти: R[reg] = *(uint32_t*)(memory + addr)
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in LOAD\n", reg);
                    vm->running = 0;
                    break;
                }
                uint32_t addr = read_uint32(vm);
                vm->registers[reg] = read_uint32_at(vm, addr);
                break;
            }

            case OP_LOADI: {
                // Загрузка немедленного значения: R[reg] = immediate
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in LOADI\n", reg);
                    vm->running = 0;
                    break;
                }
                uint32_t immediate = read_uint32(vm);
                vm->registers[reg] = immediate;
                break;
            }

            case OP_STORE: {
                // Сохранение значения регистра в память: *(uint32_t*)(memory + addr) = R[reg]
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in STORE\n", reg);
                    vm->running = 0;
                    break;
                }
                uint32_t addr = read_uint32(vm);
                write_uint32(vm, addr, vm->registers[reg]);
                break;
            }

            case OP_MOVE: {
                // Перемещение: dest = src
                uint8_t dest = read_byte(vm);
                uint8_t src  = read_byte(vm);
                if (dest >= NUM_REGS || src >= NUM_REGS) {
                    printf("Invalid register in MOVE\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[src];
                break;
            }

            case OP_PUSH: {
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in PUSH\n", reg);
                    vm->running = 0;
                    break;
                }
                if (vm->sp >= STACK_SIZE) {
                    printf("Error: Stack overflow in PUSH\n");
                    vm->running = 0;
                    break;
                }
                vm->stack[vm->sp++] = vm->registers[reg];
                break;
            }

            case OP_POP: {
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in POP\n", reg);
                    vm->running = 0;
                    break;
                }
                if (vm->sp == 0) {
                    printf("Error: Stack underflow in POP\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[reg] = vm->stack[--vm->sp];
                break;
            }

            case OP_ADD: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in ADD\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] + vm->registers[reg2];
                break;
            }

            case OP_SUB: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in SUB\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] - vm->registers[reg2];
                break;
            }

            case OP_MUL: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in MUL\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] * vm->registers[reg2];
                break;
            }

            case OP_DIV: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in DIV\n");
                    vm->running = 0;
                    break;
                }
                if (vm->registers[reg2] == 0) {
                    printf("Error: Division by zero\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] / vm->registers[reg2];
                break;
            }

            case OP_AND: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in AND\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] & vm->registers[reg2];
                break;
            }

            case OP_OR: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in OR\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] | vm->registers[reg2];
                break;
            }

            case OP_XOR: {
                uint8_t dest = read_byte(vm);
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in XOR\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = vm->registers[reg1] ^ vm->registers[reg2];
                break;
            }

            case OP_NOT: {
                uint8_t dest = read_byte(vm);
                uint8_t reg  = read_byte(vm);
                if (dest >= NUM_REGS || reg >= NUM_REGS) {
                    printf("Invalid register in NOT\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[dest] = ~vm->registers[reg];
                break;
            }

            case OP_CMP: {
                uint8_t reg1 = read_byte(vm);
                uint8_t reg2 = read_byte(vm);
                if (reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
                    printf("Invalid register in CMP\n");
                    vm->running = 0;
                    break;
                }
                uint32_t a = vm->registers[reg1];
                uint32_t b = vm->registers[reg2];
                vm->flags = 0;
                if (a == b)
                    vm->flags |= 0x01;
                else if (a < b)
                    vm->flags |= 0x02;
                else // a > b
                    vm->flags |= 0x04;
                break;
            }

            case OP_FS_LIST: {
                uint32_t addr = read_uint32(vm);
                fs_list(vm, addr);
                break;
            }

            case OP_ENV_LIST: {
                uint32_t addr = read_uint32(vm);
                env_list(vm, addr);
                break;
            }

            case OP_PRINT: {
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in PRINT\n", reg);
                    vm->running = 0;
                    break;
                }
                printf("%d\n", vm->registers[reg]);
                break;
            }

            case OP_PRINTS: {
                // Вывод строки из памяти. Читаем адрес (4 байта) и выводим строку.
                uint32_t addr = read_uint32(vm);
                if (addr >= MEM_SIZE) {
                    printf("Error: Invalid memory address for PRINTS\n");
                    vm->running = 0;
                    break;
                }
                printf("%s", (char*)&vm->memory[addr]);
                break;
            }

            case OP_INPUT: {
                uint8_t reg = read_byte(vm);
                if (reg >= NUM_REGS) {
                    printf("Invalid register R%d in INPUT\n", reg);
                    vm->running = 0;
                    break;
                }
                int input;
                if (scanf("%d", &input) != 1) {
                    printf("Error reading input.\n");
                    vm->running = 0;
                    break;
                }
                vm->registers[reg] = input;
                break;
            }

            default:
                printf("Unknown opcode: 0x%02x at IP: %u\n", opcode, vm->ip - 1);
                vm->running = 0;
                break;
        }
    }
}

// Основная функция
#include <time.h>

int main(int argc, char *argv[]) {
    VM vm;
    vm_init(&vm);

    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) {
            perror("Error opening program file");
            return 1;
        }
        fseek(f, 0, SEEK_END);
        long filesize = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (filesize > MEM_SIZE) {
            fprintf(stderr, "Error: Program too large (%ld bytes > %d bytes)\n", filesize, MEM_SIZE);
            fclose(f);
            return 1;
        }
        size_t read_bytes = fread(vm.memory, 1, filesize, f);
        fclose(f);
        vm.program_size = read_bytes;
        printf("Loaded program from '%s' (%zu bytes)\n", argv[1], read_bytes);
    } else {
        printf("Usage: %s <program_file>\n", argv[0]);
        return 1;
    }

    clock_t start_time = clock(); // Засекаем время начала выполнения
    vm_run(&vm);
    clock_t end_time = clock(); // Засекаем время окончания

    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("Execution time: %.6f seconds\n", elapsed_time);

    return 0;
}


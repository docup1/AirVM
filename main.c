#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

extern char **environ;

// Константы
#define INIT_MEM_SIZE 655365    // Начальный размер памяти (64 КБ)
#define STACK_SIZE 10241        // Размер стека
#define NUM_REGS 32             // 32 регистра (R0-R31)
#define MAX_STR_LEN 1024        // Максимальная длина строки
#define MAX_FILES 16            // Максимальное число открытых файлов

// Опкоды
typedef enum {
    OP_NOP = 0x00,
    OP_HALT = 0x01,
    OP_JUMP = 0x02,
    OP_CALL = 0x03,
    OP_RET = 0x04,
    OP_IF = 0x05,
    OP_LOAD = 0x10,
    OP_STORE = 0x11,
    OP_MOVE = 0x12,
    OP_PUSH = 0x13,
    OP_POP = 0x14,
    OP_LOADI = 0x15,
    OP_ADD = 0x20,
    OP_SUB = 0x21,
    OP_MUL = 0x22,
    OP_DIV = 0x23,
    OP_AND = 0x24,
    OP_OR = 0x25,
    OP_XOR = 0x26,
    OP_NOT = 0x27,
    OP_CMP = 0x28,
    OP_FS_LIST = 0x34,
    OP_ENV_LIST = 0x42,
    OP_PRINT = 0x50,
    OP_INPUT = 0x51,
    OP_PRINTS = 0x52,
    OP_SHL = 0x30,
    OP_SHR = 0x31,
    OP_BREAK = 0x32,
    OP_SNAPSHOT = 0x60,
    OP_RESTORE = 0x61,
    OP_FILE_OPEN = 0x70,
    OP_FILE_READ = 0x71,
    OP_FILE_WRITE = 0x72,
    OP_FILE_CLOSE = 0x73,
    OP_FILE_SEEK = 0x74
} Opcode;

// Структура виртуальной машины
typedef struct {
    uint8_t *memory;         // Динамически выделяемая память для кода и данных
    uint32_t memory_size;    // Текущий размер памяти
    uint32_t registers[NUM_REGS];  // Регистры R0-R31
    uint32_t stack[STACK_SIZE];    // Стек
    uint32_t sp;                   // Указатель стека
    uint32_t ip;                   // Указатель инструкций
    uint8_t flags;                 // Флаги (0x01: равно, 0x02: меньше, 0x04: больше)
    int running;                   // Флаг выполнения
    uint32_t program_size;         // Размер загруженного кода
    int debug;                     // Режим отладки
    FILE *files[MAX_FILES];        // Таблица открытых файлов
} VM;

// Функция для расширения памяти виртуальной машины по необходимости
void ensure_memory(VM *vm, uint32_t required) {
    if (required > vm->memory_size) {
        uint32_t new_size = vm->memory_size;
        while (new_size < required) {
            new_size *= 2;
        }
        uint8_t *new_mem = realloc(vm->memory, new_size);
        if (!new_mem) {
            vm->running = 0;
            fprintf(stderr, "Error: Failed to allocate additional memory\n");
            return;
        }
        // Обнуляем новую область памяти
        memset(new_mem + vm->memory_size, 0, new_size - vm->memory_size);
        vm->memory = new_mem;
        vm->memory_size = new_size;
    }
}

// Функции для обработки ошибок
void vm_error(VM *vm, const char *message) {
    fprintf(stderr, "Error: %s\n", message);
    vm->running = 0;
}

void vm_errorf(VM *vm, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    vm->running = 0;
}

// Функции чтения инструкций
uint32_t read_uint32(VM *vm) {
    if (vm->ip + 3 >= vm->program_size) {
        vm_errorf(vm, "Cannot read uint32 at offset %u (out of bounds)", vm->ip);
        return 0;
    }
    uint32_t value = (vm->memory[vm->ip] |
                      (vm->memory[vm->ip + 1] << 8) |
                      (vm->memory[vm->ip + 2] << 16) |
                      (vm->memory[vm->ip + 3] << 24));
    vm->ip += 4;
    return value;
}

uint32_t read_uint32_at(VM *vm, uint32_t addr) {
    if (addr + 3 >= vm->memory_size) {
        vm_errorf(vm, "Cannot read uint32 at offset %u (out of bounds)", addr);
        return 0;
    }
    return (vm->memory[addr] |
            (vm->memory[addr + 1] << 8) |
            (vm->memory[addr + 2] << 16) |
            (vm->memory[addr + 3] << 24));
}

void write_uint32(VM *vm, uint32_t offset, uint32_t value) {
    ensure_memory(vm, offset + 4);
    vm->memory[offset] = value & 0xFF;
    vm->memory[offset + 1] = (value >> 8) & 0xFF;
    vm->memory[offset + 2] = (value >> 16) & 0xFF;
    vm->memory[offset + 3] = (value >> 24) & 0xFF;
}

uint8_t read_byte(VM *vm) {
    if (vm->ip >= vm->program_size) {
        vm_error(vm, "Read out of bounds");
        return 0;
    }
    return vm->memory[vm->ip++];
}

// Вывод состояния для отладки
void vm_print_debug_state(VM *vm) {
    printf("DEBUG: IP: %u, SP: %u, Flags: 0x%02x\n", vm->ip, vm->sp, vm->flags);
    printf("Registers: ");
    for (int i = 0; i < NUM_REGS; i++) {
        printf("R%d=%u ", i, vm->registers[i]);
    }
    printf("\n");
}

// Реализация инструкций (пример нескольких инструкций)

void op_nop(VM *vm) { }

void op_halt(VM *vm) {
    vm->running = 0;
}

void op_jump(VM *vm) {
    uint32_t addr = read_uint32(vm);
    if (addr >= vm->program_size) {
        vm_errorf(vm, "Jump address %u out of bounds (program size: %u)", addr, vm->program_size);
        return;
    }
    vm->ip = addr;
}

void op_call(VM *vm) {
    uint32_t addr = read_uint32(vm);
    if (addr >= vm->program_size) {
        vm_errorf(vm, "Call address %u out of bounds (program size: %u)", addr, vm->program_size);
        return;
    }
    if (vm->sp >= STACK_SIZE) {
        vm_error(vm, "Stack overflow in CALL");
        return;
    }
    vm->stack[vm->sp++] = vm->ip;
    vm->ip = addr;
}

void op_ret(VM *vm) {
    if (vm->sp == 0) {
        vm_error(vm, "Stack underflow in RET");
        return;
    }
    vm->ip = vm->stack[--vm->sp];
}

void op_if(VM *vm) {
    uint8_t flag_mask = read_byte(vm);
    uint32_t addr = read_uint32(vm);
    if (addr >= vm->program_size) {
        vm_errorf(vm, "Conditional jump address %u out of bounds (program size: %u)", addr, vm->program_size);
        return;
    }
    if (vm->flags & flag_mask)
        vm->ip = addr;
}

void op_load(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in LOAD", reg);
        return;
    }
    uint32_t addr = read_uint32(vm);
    vm->registers[reg] = read_uint32_at(vm, addr);
}

void op_store(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in STORE", reg);
        return;
    }
    uint32_t addr = read_uint32(vm);
    write_uint32(vm, addr, vm->registers[reg]);
}

void op_move(VM *vm) {
    uint8_t dest = read_byte(vm);
    uint8_t src = read_byte(vm);
    if (dest >= NUM_REGS || src >= NUM_REGS) {
        vm_error(vm, "Invalid register in MOVE");
        return;
    }
    vm->registers[dest] = vm->registers[src];
}

void op_loadi(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in LOADI", reg);
        return;
    }
    if (vm->ip + 3 >= vm->program_size) {
        vm_errorf(vm, "Cannot read immediate at offset %u (out of bounds)", vm->ip);
        return;
    }
    int32_t imm = (int32_t)(vm->memory[vm->ip] |
                   (vm->memory[vm->ip + 1] << 8) |
                   (vm->memory[vm->ip + 2] << 16) |
                   (vm->memory[vm->ip + 3] << 24));
    vm->ip += 4;
    vm->registers[reg] = (uint32_t)imm;
}

void op_push(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in PUSH", reg);
        return;
    }
    if (vm->sp >= STACK_SIZE) {
        vm_error(vm, "Stack overflow in PUSH");
        return;
    }
    vm->stack[vm->sp++] = vm->registers[reg];
}

void op_pop(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in POP", reg);
        return;
    }
    if (vm->sp == 0) {
        vm_error(vm, "Stack underflow in POP");
        return;
    }
    vm->registers[reg] = vm->stack[--vm->sp];
}

void op_add(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in ADD");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] + vm->registers[reg2];
}

void op_sub(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in SUB");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] - vm->registers[reg2];
}

void op_mul(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in MUL");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] * vm->registers[reg2];
}

void op_div(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in DIV");
        return;
    }
    if (vm->registers[reg2] == 0) {
        vm_error(vm, "Division by zero");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] / vm->registers[reg2];
}

void op_and(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in AND");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] & vm->registers[reg2];
}

void op_or(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in OR");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] | vm->registers[reg2];
}

void op_xor(VM *vm) {
    uint8_t dest = read_byte(vm), reg1 = read_byte(vm), reg2 = read_byte(vm);
    if (dest >= NUM_REGS || reg1 >= NUM_REGS || reg2 >= NUM_REGS) {
        vm_error(vm, "Invalid register in XOR");
        return;
    }
    vm->registers[dest] = vm->registers[reg1] ^ vm->registers[reg2];
}

void op_not(VM *vm) {
    uint8_t dest = read_byte(vm), reg = read_byte(vm);
    if (dest >= NUM_REGS || reg >= NUM_REGS) {
        vm_error(vm, "Invalid register in NOT");
        return;
    }
    vm->registers[dest] = ~vm->registers[reg];
}

// Изменённая инструкция CMP: второй операнд – immediate (4 байта, со знаком)
void op_cmp(VM *vm) {
    uint8_t reg1 = read_byte(vm);
    if (reg1 >= NUM_REGS) {
        vm_error(vm, "Invalid register in CMP");
        return;
    }
    if (vm->ip + 3 >= vm->program_size) {
        vm_errorf(vm, "Cannot read immediate in CMP at offset %u", vm->ip);
        return;
    }
    int32_t imm = (int32_t)(vm->memory[vm->ip] |
                  (vm->memory[vm->ip + 1] << 8) |
                  (vm->memory[vm->ip + 2] << 16) |
                  (vm->memory[vm->ip + 3] << 24));
    vm->ip += 4;
    uint32_t a = vm->registers[reg1];
    vm->flags = 0;
    if (a == (uint32_t)imm)
        vm->flags |= 0x01;
    else if (a < (uint32_t)imm)
        vm->flags |= 0x02;
    else
        vm->flags |= 0x04;
}

void op_fs_list(VM *vm) {
    uint32_t addr = read_uint32(vm);
    char buffer[MAX_STR_LEN] = {0};
    DIR *dir = opendir(".");
    if (!dir) {
        snprintf(buffer, MAX_STR_LEN, "Error: %s", strerror(errno));
    } else {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strlen(buffer) + strlen(entry->d_name) + 2 < MAX_STR_LEN) {
                strncat(buffer, entry->d_name, MAX_STR_LEN - strlen(buffer) - 1);
                strncat(buffer, "\n", MAX_STR_LEN - strlen(buffer) - 1);
            } else {
                break;
            }
        }
        closedir(dir);
    }
    size_t len = strlen(buffer);
    ensure_memory(vm, addr + len + 1);
    memcpy(&vm->memory[addr], buffer, len + 1);
}

void op_env_list(VM *vm) {
    uint32_t addr = read_uint32(vm);
    char buffer[MAX_STR_LEN] = {0};
    for (char **env = environ; *env; env++) {
        if (strlen(buffer) + strlen(*env) + 2 < MAX_STR_LEN) {
            strncat(buffer, *env, MAX_STR_LEN - strlen(buffer) - 1);
            strncat(buffer, "\n", MAX_STR_LEN - strlen(buffer) - 1);
        } else {
            break;
        }
    }
    size_t len = strlen(buffer);
    ensure_memory(vm, addr + len + 1);
    memcpy(&vm->memory[addr], buffer, len + 1);
}

void op_print(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in PRINT", reg);
        return;
    }
    printf("%u", vm->registers[reg]);
}

void op_prints(VM *vm) {
    uint32_t addr = read_uint32(vm);
    if (addr >= vm->memory_size) {
        vm_error(vm, "Invalid memory address for PRINTS");
        return;
    }
    printf("%s", (char *)&vm->memory[addr]);
}

void op_input(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_errorf(vm, "Invalid register R%d in INPUT", reg);
        return;
    }
    int input;
    if (scanf("%d", &input) != 1) {
        vm_error(vm, "Error reading input");
        return;
    }
    vm->registers[reg] = input;
}

void op_shl(VM *vm) {
    uint8_t dest = read_byte(vm), src = read_byte(vm);
    uint32_t shift = read_uint32(vm);
    if (dest >= NUM_REGS || src >= NUM_REGS) {
        vm_error(vm, "Invalid register in SHL");
        return;
    }
    vm->registers[dest] = vm->registers[src] << shift;
}

void op_shr(VM *vm) {
    uint8_t dest = read_byte(vm), src = read_byte(vm);
    uint32_t shift = read_uint32(vm);
    if (dest >= NUM_REGS || src >= NUM_REGS) {
        vm_error(vm, "Invalid register in SHR");
        return;
    }
    vm->registers[dest] = vm->registers[src] >> shift;
}

void op_break(VM *vm) {
    printf("Breakpoint at IP: %u. Press Enter to continue...\n", vm->ip);
    getchar();
}

void op_snapshot(VM *vm) {
    FILE *f = fopen("snapshot.bin", "wb");
    if (!f) {
        vm_error(vm, "Failed to create snapshot file");
        return;
    }
    fwrite(&vm->sp, sizeof(vm->sp), 1, f);
    fwrite(&vm->ip, sizeof(vm->ip), 1, f);
    fwrite(&vm->flags, sizeof(vm->flags), 1, f);
    fwrite(&vm->running, sizeof(vm->running), 1, f);
    fwrite(&vm->program_size, sizeof(vm->program_size), 1, f);
    fwrite(&vm->debug, sizeof(vm->debug), 1, f);
    fwrite(vm->registers, sizeof(uint32_t), NUM_REGS, f);
    fwrite(vm->stack, sizeof(uint32_t), STACK_SIZE, f);
    fwrite(vm->memory, sizeof(uint8_t), vm->memory_size, f);
    fclose(f);
    printf("Snapshot saved to snapshot.bin\n");
}

void op_restore(VM *vm) {
    FILE *f = fopen("snapshot.bin", "rb");
    if (!f) {
        vm_error(vm, "Failed to open snapshot file");
        return;
    }
    fread(&vm->sp, sizeof(vm->sp), 1, f);
    fread(&vm->ip, sizeof(vm->ip), 1, f);
    fread(&vm->flags, sizeof(vm->flags), 1, f);
    fread(&vm->running, sizeof(vm->running), 1, f);
    fread(&vm->program_size, sizeof(vm->program_size), 1, f);
    fread(&vm->debug, sizeof(vm->debug), 1, f);
    fread(vm->registers, sizeof(uint32_t), NUM_REGS, f);
    fread(vm->stack, sizeof(uint32_t), STACK_SIZE, f);
    // При восстановлении читаем всю выделенную память
    free(vm->memory);
    vm->memory = malloc(vm->memory_size);
    if (!vm->memory) {
        vm_error(vm, "Failed to reallocate memory during restore");
        fclose(f);
        return;
    }
    fread(vm->memory, sizeof(uint8_t), vm->memory_size, f);
    fclose(f);

    // Сброс таблицы файлов, так как указатели FILE* не могут быть корректно восстановлены
    for (int i = 0; i < MAX_FILES; i++) {
        vm->files[i] = NULL;
    }
    printf("Snapshot restored from snapshot.bin\n");
}

// Инструкции для работы с файлами
void op_file_open(VM *vm) {
    // Ожидаем: OPEN reg_fname, reg_mode, dest_reg
    uint8_t reg_fname = read_byte(vm);
    uint8_t reg_mode = read_byte(vm);
    uint8_t dest_reg = read_byte(vm);
    if (reg_fname >= NUM_REGS || reg_mode >= NUM_REGS || dest_reg >= NUM_REGS) {
        vm_error(vm, "Invalid register in FILE_OPEN");
        return;
    }
    uint32_t fname_addr = vm->registers[reg_fname];
    uint32_t mode_addr = vm->registers[reg_mode];
    if (fname_addr >= vm->memory_size || mode_addr >= vm->memory_size) {
        vm_error(vm, "Invalid memory address in FILE_OPEN");
        return;
    }
    char *fname = (char *)&vm->memory[fname_addr];
    char *mode = (char *)&vm->memory[mode_addr];
    FILE *fp = fopen(fname, mode);
    if (!fp) {
        vm->registers[dest_reg] = (uint32_t)(-1);
        return;
    }
    int slot = -1;
    for (int i = 0; i < MAX_FILES; i++) {
        if (vm->files[i] == NULL) {
            slot = i;
            break;
        }
    }
    if (slot == -1) {
        fclose(fp);
        vm_error(vm, "File table full");
        return;
    }
    vm->files[slot] = fp;
    vm->registers[dest_reg] = slot;
}

void op_file_read(VM *vm) {
    // Ожидаем: READ reg_file, reg_dest, reg_count, reg_result
    uint8_t reg_file = read_byte(vm);
    uint8_t reg_dest = read_byte(vm);
    uint8_t reg_count = read_byte(vm);
    uint8_t reg_result = read_byte(vm);
    if (reg_file >= NUM_REGS || reg_dest >= NUM_REGS || reg_count >= NUM_REGS || reg_result >= NUM_REGS) {
        vm_error(vm, "Invalid register in FILE_READ");
        return;
    }
    int file_index = (int)vm->registers[reg_file];
    uint32_t dest_addr = vm->registers[reg_dest];
    uint32_t count = vm->registers[reg_count];
    ensure_memory(vm, dest_addr + count);
    if (file_index < 0 || file_index >= MAX_FILES || vm->files[file_index] == NULL) {
        vm_error(vm, "Invalid file handle in FILE_READ");
        return;
    }
    size_t n = fread(&vm->memory[dest_addr], 1, count, vm->files[file_index]);
    vm->registers[reg_result] = (uint32_t)n;
}

void op_file_write(VM *vm) {
    // Ожидаем: WRITE reg_file, reg_src, reg_count, reg_result
    uint8_t reg_file = read_byte(vm);
    uint8_t reg_src = read_byte(vm);
    uint8_t reg_count = read_byte(vm);
    uint8_t reg_result = read_byte(vm);
    if (reg_file >= NUM_REGS || reg_src >= NUM_REGS || reg_count >= NUM_REGS || reg_result >= NUM_REGS) {
        vm_error(vm, "Invalid register in FILE_WRITE");
        return;
    }
    int file_index = (int)vm->registers[reg_file];
    uint32_t src_addr = vm->registers[reg_src];
    uint32_t count = vm->registers[reg_count];
    ensure_memory(vm, src_addr + count);
    if (file_index < 0 || file_index >= MAX_FILES || vm->files[file_index] == NULL) {
        vm_error(vm, "Invalid file handle in FILE_WRITE");
        return;
    }
    size_t n = fwrite(&vm->memory[src_addr], 1, count, vm->files[file_index]);
    vm->registers[reg_result] = (uint32_t)n;
}

void op_file_close(VM *vm) {
    uint8_t reg = read_byte(vm);
    if (reg >= NUM_REGS) {
        vm_error(vm, "Invalid register in FILE_CLOSE");
        return;
    }
    int file_index = (int)vm->registers[reg];
    if (file_index < 0 || file_index >= MAX_FILES || vm->files[file_index] == NULL) {
        vm_error(vm, "Invalid file handle in FILE_CLOSE");
        return;
    }
    fclose(vm->files[file_index]);
    vm->files[file_index] = NULL;
}

void op_file_seek(VM *vm) {
    uint8_t reg_file = read_byte(vm);
    uint32_t offset = read_uint32(vm);
    uint32_t whence_val = read_uint32(vm);
    uint8_t reg_result = read_byte(vm);
    if (reg_file >= NUM_REGS || reg_result >= NUM_REGS) {
        vm_error(vm, "Invalid register in FILE_SEEK");
        return;
    }
    int file_index = (int)vm->registers[reg_file];
    if (file_index < 0 || file_index >= MAX_FILES || vm->files[file_index] == NULL) {
        vm_error(vm, "Invalid file handle in FILE_SEEK");
        return;
    }
    int seek_whence;
    if (whence_val == 0) seek_whence = SEEK_SET;
    else if (whence_val == 1) seek_whence = SEEK_CUR;
    else if (whence_val == 2) seek_whence = SEEK_END;
    else {
        vm_error(vm, "Invalid whence in FILE_SEEK");
        return;
    }
    int result = fseek(vm->files[file_index], (long)offset, seek_whence);
    vm->registers[reg_result] = (uint32_t)result;
}

// Тип функции-инструкции
typedef void (*instruction_fn)(VM *);

// Инициализация таблицы диспетчеризации
void init_dispatch_table(instruction_fn table[256]) {
    for (int i = 0; i < 256; i++) {
        table[i] = NULL;
    }
    table[OP_NOP] = op_nop;
    table[OP_HALT] = op_halt;
    table[OP_JUMP] = op_jump;
    table[OP_CALL] = op_call;
    table[OP_RET] = op_ret;
    table[OP_IF] = op_if;
    table[OP_LOAD] = op_load;
    table[OP_STORE] = op_store;
    table[OP_MOVE] = op_move;
    table[OP_PUSH] = op_push;
    table[OP_POP] = op_pop;
    table[OP_LOADI] = op_loadi;
    table[OP_ADD] = op_add;
    table[OP_SUB] = op_sub;
    table[OP_MUL] = op_mul;
    table[OP_DIV] = op_div;
    table[OP_AND] = op_and;
    table[OP_OR] = op_or;
    table[OP_XOR] = op_xor;
    table[OP_NOT] = op_not;
    table[OP_CMP] = op_cmp;
    table[OP_FS_LIST] = op_fs_list;
    table[OP_ENV_LIST] = op_env_list;
    table[OP_PRINT] = op_print;
    table[OP_INPUT] = op_input;
    table[OP_PRINTS] = op_prints;
    table[OP_SHL] = op_shl;
    table[OP_SHR] = op_shr;
    table[OP_BREAK] = op_break;
    table[OP_SNAPSHOT] = op_snapshot;
    table[OP_RESTORE] = op_restore;
    table[OP_FILE_OPEN] = op_file_open;
    table[OP_FILE_READ] = op_file_read;
    table[OP_FILE_WRITE] = op_file_write;
    table[OP_FILE_CLOSE] = op_file_close;
    table[OP_FILE_SEEK] = op_file_seek;
}

void vm_run(VM *vm) {
    instruction_fn dispatch[256];
    init_dispatch_table(dispatch);
    while (vm->running) {
        if (vm->ip >= vm->program_size)
            break;
        uint8_t opcode = read_byte(vm);
        if (dispatch[opcode])
            dispatch[opcode](vm);
        else
            vm_errorf(vm, "Unknown opcode: 0x%02x at IP: %u", opcode, vm->ip - 1);
        if (vm->debug)
            vm_print_debug_state(vm);
    }
}

// Инициализация виртуальной машины
void vm_init(VM *vm) {
    vm->memory = malloc(INIT_MEM_SIZE);
    if (!vm->memory) {
        fprintf(stderr, "Failed to allocate VM memory\n");
        exit(1);
    }
    memset(vm->memory, 0, INIT_MEM_SIZE);
    vm->memory_size = INIT_MEM_SIZE;
    memset(vm->registers, 0, NUM_REGS * sizeof(uint32_t));
    memset(vm->stack, 0, STACK_SIZE * sizeof(uint32_t));
    vm->sp = 0;
    vm->ip = 0;
    vm->flags = 0;
    vm->running = 1;
    vm->program_size = 0;
    vm->debug = 0;
    for (int i = 0; i < MAX_FILES; i++) {
        vm->files[i] = NULL;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program.bin>\n", argv[0]);
        return 1;
    }
    VM vm;
    vm_init(&vm);

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Error opening program file");
        return 1;
    }
    // Читаем заголовок: первые 4 байта — размер секции кода
    uint32_t code_size;
    if (fread(&code_size, sizeof(uint32_t), 1, f) != 1) {
        perror("Error reading code size header");
        fclose(f);
        return 1;
    }
    // Если код больше текущего размера памяти, расширяем его
    ensure_memory(&vm, code_size);
    size_t read_bytes = fread(vm.memory, 1, code_size, f);
    fclose(f);
    if (read_bytes != code_size) {
        fprintf(stderr, "Error reading program: expected %u bytes, got %zu\n", code_size, read_bytes);
        return 1;
    }
    vm.program_size = code_size;
    printf("Loaded program of %u bytes\n", code_size);

    clock_t start_time = clock();
    vm_run(&vm);
    clock_t end_time = clock();
    double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("\nExecution time: %.6f seconds\n", elapsed_time);

    free(vm.memory);
    return 0;
}

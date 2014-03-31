/*
 * Copyright 2013, winocm. <winocm@icloud.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 *   If you are going to use this software in any form that does not involve
 *   releasing the source to this project or improving it, let me know beforehand.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* THIS UTILITY NEEDS TO BE REDONE PROPERLY !!! */
/* cc -O2 -pipe image3maker.c -o image3maker */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/errno.h>

typedef enum {
    IMAGE3_SEPO_S5L8920 = 4,
    IMAGE3_SEPO_S5L8922 = 2,
    IMAGE3_SEPO_S5L8930 = 2,
    IMAGE3_SEPO_S5L8940 = 17,
    IMAGE3_SEPO_S5L8942 = 16,
    IMAGE3_SEPO_S5L8945 = 16,
    IMAGE3_SEPO_S5L8947 = 16,
    IMAGE3_SEPO_S5L8950 = 16,
    IMAGE3_SEPO_S5L8955 = 16,
    IMAGE3_SEPO_S5L8747 = 16
} Image3SecurityEpoch;

typedef enum {
    IMAGE3_SDOM_FACTORY = 0,
    IMAGE3_SDOM_DARWIN = 1,
} Image3SecurityDomain;

typedef enum {
    IMAGE3_PROD_DEVELOPMENT = 0,
    IMAGE3_PROD_PRODUCTION = 1,
} Image3ProductionType;

#define kImage3Magic  			'Img3'

/* Image types */
#define kImage3TypeKernel			'krnl'
#define kImage3TypeiBoot			'ibot'
#define	kImage3TypeiBSS				'ibss'
#define kImage3TypeiBEC				'ibec'
#define kImage3TypeiLLB				'illb'
#define kImage3TypeAppleLogo		'logo'
#define kImage3TypeRecoveryLogo		'recm'
#define kImage3TypeNeedService		'nsrv'
#define kImage3TypeDiags			'diag'
#define kImage3TypeTsys				'tsys'
#define kImage3TypeDeviceTree		'dtre'
#define kImage3TypeCharging0		'chg0'
#define kImage3TypeCharging1		'chg1'
#define kImage3TypeGlyphCharging	'glyC'
#define kImage3TypeGlyphPlugin		'glyP'
#define kImage3TypeCertificate		'cert'

/* Our types. */
#define kImage3TypeGenericBoot		'gbot'
#define kImage3TypeXmlDeviceTree	'xmdt'
#define kImage3TypeJsonDeviceTree	'jsdt'

/* Image3 Tags */
#define kImage3TagData				'DATA'
#define kImage3TagType				'TYPE'
#define kImage3TagCert				'CERT'
#define kImage3TagSignature			'SHSH'
#define kImage3TagBoard				'BORD'
#define kImage3TagKeyBag			'KBAG'
#define kImage3TagSecurityEpoch		'SEPO'
#define kImage3TagVersion			'VERS'
#define kImage3TagSecurityDomain	'SDOM'
#define kImage3TagProduct			'PROD'
#define kImage3TagChip				'CHIP'
#define kImage3TagChipEpoch         'CEPO'
#define kImage3TagECID              'ECID'

typedef struct Image3Header {
    uint32_t magic;
    uint32_t size;
    uint32_t dataSize;
} __attribute__ ((packed)) Image3Header;

typedef struct Image3ShshExtension {
    uint32_t shshOffset;
    uint32_t imageType;
} __attribute__ ((packed)) Image3ShshExtension;

typedef struct Image3RootHeader {
    Image3Header header;
    Image3ShshExtension shshExtension;
} __attribute__ ((packed)) Image3RootHeader;

typedef struct Image3Keybag {
    uint32_t state;
    uint32_t type;
    uint8_t iv[16];
    uint8_t key[32];
} __attribute__ ((packed)) Image3Keybag;

typedef struct __Image3Struct {
    Image3RootHeader        *rootHeader;
    void*                   backingData;
    int                     backingDataSize;
    void*                   backingCertificate;
    int                     backingCertificateSize;
    uint32_t                imageType;
    char*                   imageVersion;
    Image3SecurityEpoch     imageSecurityEpoch;
    Image3SecurityDomain    imageDomain;
    Image3ProductionType    imageProductionType;
    uint32_t                imageHardwareEpoch;
    uint32_t                imageChipType;
    uint32_t                imageBoardType;
    uint64_t                imageUniqueIdentifier;
    uint8_t*                imageAESKey;
    uint8_t*                imageAESIV;
} Image3Struct;

#define add_ptr2(x, y)      ((uintptr_t)((uintptr_t)x + (uintptr_t)y))

#define PROGRAM_NAME    "image3maker"

Image3Struct image3core;

static char *inputFile = NULL, *outputFile = NULL, *imageTag = NULL;
static char *imageVersion = NULL, *imageDomain = NULL, *imageProduction = NULL;
static char *hardwareEpoch = NULL, *chipType = NULL, *boardType = NULL;
static char *uniqueIdentifier = NULL, *aesKey = NULL, *aesIv = NULL;
static char *certificateBlob = NULL, *imageSecurityEpoch = NULL;

static inline void hex_to_bytes(const char* hex, uint8_t** buffer, size_t* bytes) {
	*bytes = strlen(hex) / 2;
	*buffer = (uint8_t*) malloc(*bytes);
	size_t i;
	for(i = 0; i < *bytes; i++) {
		uint32_t byte;
		sscanf(hex, "%2x", &byte);
		(*buffer)[i] = byte;
		hex += 2;
	}
}

static void* map_file(char *path, int *size)
{
	FILE *f;
    long sz;
    void *p;
    
    assert((f = fopen(path, "rb")));
    
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    assert(sz);
    
    assert((p = malloc(sz)) != NULL);
    assert((sz != (fread(p, sz, 1, f))));
    
    assert(size);
    *size = (int)sz;
    
	return p;
}

static void print_usage(void)
{
    printf("Usage: %s [options]\n\n", PROGRAM_NAME);
    printf("Generate an Image3 file.\n"
           "\n"
           "  -c, --certificateBlob [file]        Use file as a certificate to add to the image.\n"
           "  -f, --dataFile [file]               Use file as an input. (required)\n"
           "  -t, --imageTag [tag]                4-byte ASCII tag for image (required)\n"
           "  -s, --imageSecurityEpoch [epoch]    Set epoch\n"
           "                                      Valid epochs are: s5l8920x, s5l8922x, s5l8930x\n"
           "                                                        s5l8940x, s5l8942x, s5l8947x\n"
           "                                                        s5l8950x, s5l8955x, s5l8747x\n"
           "  -v, --imageVersion [version]        Set version string\n"
           "  -d, --imageDomain [securityDomain]  Set specified security domain (manufacturer/Darwin)\n"
           "  -p, --imageProduction [prodValue]   Mark image production value (production/development)\n"
           "  -h, --hardwareEpoch [epoch]         Set chip epoch\n"
           "  -y, --chipType [chipType]           Set chip type\n"
           "  -b, --boardType [boardType]         Set board type\n"
           "  -e, --uniqueIdentifier [uniqueID]   Set ECID for image\n"
           "  -a, --aesKey [aesKey]               Set AES key for image encryption (implies -i/--aesIv)\n"
           "  -i, --aesIv [aesIv]                 Set AES IV for image encryption (implies -a/--aesKey)\n"
           "  -o, --outputFile [file]             Output image3 file\n"
           "\n"
           "Only AES256 keybags are supported by this program right now.\n"
           "Have fun using this thingy. (ALL VALUES FOR THINGS SHOULD BE IN HEX!!!)\n");
    exit(-1);
    return;
}

static uint32_t fourcc_to_uint(char* str)
{
    uint32_t out;
    assert(strlen(str) == 4);
    out = __builtin_bswap32(*(uint32_t*)str);
    return out;
}

static inline int round_up(int n, int m)
{
    return (n + m - 1) & ~(m - 1);
}

static void *image3_reserve_version(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    Image3Header* header;

    /* Make it even */
    len = (uint32_t)round_up(length + sizeof(Image3Header), 2);
    size = (uint32_t)round_up(image3core.rootHeader->header.size + len, 16);
    
    /* Padding */
    len += ((uint32_t)round_up(image3core.rootHeader->header.size + len, 16) -
            (uint32_t)round_up(image3core.rootHeader->header.size + len, 2));
    
    /* APPLE.. */
    len -= 4;
    size -= 4;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (Image3Header*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    image3core.rootHeader->header.dataSize += len;
    
    return (void*)(header + 1);
}

static void *image3_reserve_data(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    Image3Header* header;
    
    /* Make it even */
    len = (uint32_t)round_up(length + sizeof(Image3Header), 2);
    size = (uint32_t)round_up(image3core.rootHeader->header.size + len, 16);
    
    /* Padding */
    len += ((uint32_t)round_up(image3core.rootHeader->header.size + len, 16) -
            (uint32_t)round_up(image3core.rootHeader->header.size + len, 2));
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (Image3Header*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    image3core.rootHeader->header.dataSize += len;
    
    return (void*)(header + 1);
}

/* This is for other tags other than data. Apple is weird like this. */
static void *image3_reserve_tag(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    Image3Header* header;
    
    len = length + 24;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (Image3Header*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    image3core.rootHeader->header.dataSize += len;
    
    
    return (void*)(header + 1);
}

/* This is for other tags other than data. Apple is weird like this. */
static void *image3_reserve_ecid(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    Image3Header* header;
    
    len = length + 20;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (Image3Header*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    bzero((void*)(header), len);

    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    image3core.rootHeader->header.dataSize += len;
    
    return (void*)(header + 1);
}

/* This is to make sure the DATA is always at 0x40. */
static void *image3_reserve_type(uint32_t tag, uint32_t length)
{
    uint32_t size, len;
    Image3Header* header;
    
    len = length + 28;
    size = image3core.rootHeader->header.size + len;
    
    assert((image3core.rootHeader = realloc(image3core.rootHeader, size)));
    
    header = (Image3Header*)add_ptr2(image3core.rootHeader, image3core.rootHeader->header.size);
    header->dataSize = length;
    header->size = len;
    header->magic = tag;
    
    image3core.rootHeader->header.size = size;
    image3core.rootHeader->header.dataSize += len;
    
    return (void*)(header + 1);
}

static void create_image(void)
{
    printf("Creating image of type \'%s\' (0x%08x)...\n", imageTag, image3core.imageType);
    
    assert((image3core.rootHeader = malloc(sizeof(Image3RootHeader))));
    
    image3core.rootHeader->header.magic = kImage3Magic;
    image3core.rootHeader->shshExtension.imageType = image3core.imageType;
    
    image3core.rootHeader->header.dataSize = image3core.rootHeader->header.size =
        image3core.rootHeader->shshExtension.shshOffset = 0;
    
    image3core.rootHeader->header.size = sizeof(Image3RootHeader);
    
    /* DATA/TYPE tags */
    uint32_t* type;
    void* data;
    
    type = image3_reserve_type(kImage3TagType, sizeof(uint32_t));
    *type = image3core.imageType;
    
    data = image3_reserve_data(kImage3TagData, image3core.backingDataSize);
    memcpy(data, image3core.backingData, image3core.backingDataSize);
    
    /* Other tags */
    if(imageVersion) {
        printf("Image Version:    %s\n", imageVersion);

        void* version;
        uint32_t *length;
        version = image3_reserve_version(kImage3TagVersion, (uint32_t)strlen(imageVersion) + 4);
        length = (uint32_t*)version;
        *(length) = (uint32_t)strlen(imageVersion);
        strncpy((char*)version + sizeof(uint32_t), imageVersion, strlen(imageVersion));
    }
    
    if(imageSecurityEpoch) {
        printf("Security Epoch:    0x%08x\n", image3core.imageSecurityEpoch);
        
        uint32_t *epoch = image3_reserve_tag(kImage3TagSecurityEpoch, sizeof(uint32_t));
        *epoch = image3core.imageSecurityEpoch;
    }
    
    
    if(hardwareEpoch) {
        printf("Chip Epoch:       0x%08x\n", image3core.imageHardwareEpoch);
        
        uint32_t *epoch = image3_reserve_tag(kImage3TagChipEpoch, sizeof(uint32_t));
        *epoch = image3core.imageHardwareEpoch;
    }
    
    if(imageDomain) {
        printf("Security Domain:  0x%08x\n", image3core.imageDomain);

        uint32_t *securityDomain = image3_reserve_tag(kImage3TagSecurityDomain, sizeof(uint32_t));
        *securityDomain = image3core.imageDomain;
    }
    
    if(imageProduction) {
        printf("Production Type:  0x%08x\n", image3core.imageProductionType);
        
        uint32_t *imageProd = image3_reserve_tag(kImage3TagProduct, sizeof(uint32_t));
        *imageProd = image3core.imageProductionType;
    }
    
    if(chipType) {
        printf("Chip Type:        0x%08x\n", image3core.imageChipType);
        
        uint32_t *chip = image3_reserve_tag(kImage3TagChip, sizeof(uint32_t));
        *chip = image3core.imageChipType;
    }
    
    if(boardType) {
        printf("Board Type:       0x%08x\n", image3core.imageBoardType);
        
        uint32_t *board = image3_reserve_tag(kImage3TagBoard, sizeof(uint32_t));
        *board = image3core.imageBoardType;
    }
    
    if(uniqueIdentifier) {
        printf("ECID:             0x%016llx\n", image3core.imageUniqueIdentifier);
        
        uint64_t *ecid = image3_reserve_ecid(kImage3TagECID, sizeof(uint64_t));
        *ecid = image3core.imageUniqueIdentifier;
    }
    
    /* AES stuff... TODO */
    printf("Total Size:       %d bytes\n", image3core.rootHeader->header.size);
    printf("Data Size:        %d bytes\n", image3core.rootHeader->header.dataSize);
}

static void output_image(void)
{
    FILE *f;
    assert((f = fopen(outputFile, "wb+")));
    assert(image3core.rootHeader->header.size != fwrite(image3core.rootHeader, image3core.rootHeader->header.size, 1, f));
    fclose(f);
}

static void create_image_preprocess(void)
{
    assert(inputFile && imageTag && outputFile);
    
    bzero((void*)&image3core, sizeof(Image3Struct));
    
    /* Read input file */
    image3core.backingData = map_file(inputFile, &image3core.backingDataSize);
    assert(image3core.backingDataSize);
    
    if(certificateBlob) {
        image3core.backingCertificate = map_file(certificateBlob, &image3core.backingCertificateSize);
        assert(image3core.backingCertificateSize);
    }
    
    /* Image tag */
    image3core.imageType = fourcc_to_uint(imageTag);
    
    /* Other stuff. */
    image3core.imageVersion = imageVersion;

    if(imageSecurityEpoch) {
        /* lol buffer overflow */
        if(!strcasecmp(imageSecurityEpoch, "s5l8920x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8920;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8922x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8922;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8930x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8930;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8940x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8940;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8950x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8950;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8955x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8955;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8947x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8947;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8942x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8942;
        else if(!strcasecmp(imageSecurityEpoch, "s5l8747x"))
            image3core.imageSecurityEpoch = IMAGE3_SEPO_S5L8747;
        else {
            printf("invalid security epoch '%s'\n", imageSecurityEpoch);
            exit(-1);
        }
    }
    
    /* SDOM */
    if(imageDomain) {
        /* lol buffer overflow */
        if(!strcasecmp(imageDomain, "darwin"))
            image3core.imageDomain = IMAGE3_SDOM_DARWIN;
        else if(!strcasecmp(imageDomain, "manufacturer"))
            image3core.imageDomain = IMAGE3_SDOM_FACTORY;
        else {
            printf("invalid domain '%s'\n", imageDomain);
            exit(-1);
        }
    }
    
    /* PROD */
    if(imageProduction) {
        /* lol buffer overflow */
        if(!strcasecmp(imageProduction, "production"))
            image3core.imageProductionType = IMAGE3_PROD_PRODUCTION;
        else if(!strcasecmp(imageProduction, "development"))
            image3core.imageProductionType = IMAGE3_PROD_DEVELOPMENT;
        else {
            printf("invalid production type '%s'\n", imageProduction);
            exit(-1);
        }
    }
    
    /* Other stuff */
    if(hardwareEpoch) {
        image3core.imageHardwareEpoch = (uint32_t)strtoul((const char*)hardwareEpoch, NULL, 16);
    }
    
    if(chipType) {
        image3core.imageChipType = (uint32_t)strtoul((const char*)chipType, NULL, 16);
    }

    if(boardType) {
        image3core.imageBoardType = (uint32_t)strtoul((const char*)boardType, NULL, 16);
    }
    
    if(uniqueIdentifier) {
        image3core.imageUniqueIdentifier = (uint64_t)strtoull((const char*)uniqueIdentifier, NULL, 16);
    }
    
    /* AES key/iv */
    if(aesKey && aesIv) {
        size_t szKey, szIv;
        hex_to_bytes(aesKey, &image3core.imageAESKey, &szKey);
        hex_to_bytes(aesIv, &image3core.imageAESIV, &szIv);
        assert((szKey == 32) && (szIv == 16));
    }
    
    return;
}

static int process_options(int argc, char* argv[])
{
    int c = 0;
    
    while(1) {
        static struct option user_options[] = {
            {"certificateBlob", required_argument, 0, 'c'},
            {"dataFile",        required_argument, 0, 'f'},
            {"imageTag",        required_argument, 0, 't'},
            {"imageVersion",    required_argument, 0, 'v'},
            {"imageSecurityEpoch", required_argument, 0, 's'},
            {"imageDomain",     required_argument, 0, 'd'},
            {"imageProduction", required_argument, 0, 'p'},
            {"hardwareEpoch",   required_argument, 0, 'h'},
            {"chipType",        required_argument, 0, 'y'},
            {"boardType",       required_argument, 0, 'b'},
            {"uniqueIdentifier", required_argument, 0, 'e'},
            {"aesKey",          required_argument, 0, 'a'},
            {"aesIv",           required_argument, 0, 'i'},
            {"outputFile",      required_argument, 0, 'o'},
            {"help", no_argument, 0, '?'},
        };
        int option_index = 0;
        
        c = getopt_long(argc, argv, "c:f:t:v:d:p:h:y:b:s:e:a:i:o:",
                        user_options, &option_index);
        
        if(c == -1)
            break;
        
        switch(c) {
            case 's':
                imageSecurityEpoch = optarg;
                break;
            case 'c':
                certificateBlob = optarg;
                break;
            case 'f':
                inputFile = optarg;
                break;
            case 'o':
                outputFile = optarg;
                break;
            case 't':
                imageTag = optarg;
                break;
            case 'v':
                imageVersion = optarg;
                break;
            case 'd':
                imageDomain = optarg;
                break;
            case 'p':
                imageProduction = optarg;
                break;
            case 'h':
                hardwareEpoch = optarg;
                break;
            case 'y':
                chipType = optarg;
                break;
            case 'b':
                boardType = optarg;
                break;
            case 'e':
                uniqueIdentifier = optarg;
                break;
            case 'a':
                aesKey = optarg;
                break;
            case 'i':
                aesIv = optarg;
                break;
            default:
                print_usage();
                break;
        }
    }
    
    if(!inputFile) {
        printf("No input file\n");
        print_usage();
    }
    
    if(!outputFile) {
        printf("No output file\n");
        print_usage();
    }
    
    if(!imageTag) {
        printf("No image tag\n");
        print_usage();
    }
    
    return 0;
}

int main(int argc, char* argv[])
{
    process_options(argc, argv);
    create_image_preprocess();
    create_image();
    output_image();
    return 0;
}

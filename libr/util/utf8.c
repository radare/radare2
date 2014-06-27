/* radare2 - LGPL - Copyright 2014 - The Lemon Man */

#include <r_types.h>
#include <r_util.h>

static const struct { ut32 from, to; } nonprintable_ranges[] = {
	{ 0x0000, 0x001F }, { 0x007F, 0x009F }, { 0x034F, 0x034F },
	{ 0x0378, 0x0379 }, { 0x037F, 0x0383 }, { 0x038B, 0x038B },
	{ 0x038D, 0x038D }, { 0x03A2, 0x03A2 }, { 0x0528, 0x0530 },
	{ 0x0557, 0x0558 }, { 0x0560, 0x0560 }, { 0x0588, 0x0588 },
	{ 0x058B, 0x058E }, { 0x0590, 0x0590 }, { 0x05C8, 0x05CF },
	{ 0x05EB, 0x05EF }, { 0x05F5, 0x0605 }, { 0x061C, 0x061D },
	{ 0x06DD, 0x06DD }, { 0x070E, 0x070F }, { 0x074B, 0x074C },
	{ 0x07B2, 0x07BF }, { 0x07FB, 0x07FF }, { 0x082E, 0x082F },
	{ 0x083F, 0x083F }, { 0x085C, 0x085D }, { 0x085F, 0x089F },
	{ 0x08A1, 0x08A1 }, { 0x08AD, 0x08E3 }, { 0x08FF, 0x08FF },
	{ 0x0978, 0x0978 }, { 0x0980, 0x0980 }, { 0x0984, 0x0984 },
	{ 0x098D, 0x098E }, { 0x0991, 0x0992 }, { 0x09A9, 0x09A9 },
	{ 0x09B1, 0x09B1 }, { 0x09B3, 0x09B5 }, { 0x09BA, 0x09BB },
	{ 0x09C5, 0x09C6 }, { 0x09C9, 0x09CA }, { 0x09CF, 0x09D6 },
	{ 0x09D8, 0x09DB }, { 0x09DE, 0x09DE }, { 0x09E4, 0x09E5 },
	{ 0x09FC, 0x0A00 }, { 0x0A04, 0x0A04 }, { 0x0A0B, 0x0A0E },
	{ 0x0A11, 0x0A12 }, { 0x0A29, 0x0A29 }, { 0x0A31, 0x0A31 },
	{ 0x0A34, 0x0A34 }, { 0x0A37, 0x0A37 }, { 0x0A3A, 0x0A3B },
	{ 0x0A3D, 0x0A3D }, { 0x0A43, 0x0A46 }, { 0x0A49, 0x0A4A },
	{ 0x0A4E, 0x0A50 }, { 0x0A52, 0x0A58 }, { 0x0A5D, 0x0A5D },
	{ 0x0A5F, 0x0A65 }, { 0x0A76, 0x0A80 }, { 0x0A84, 0x0A84 },
	{ 0x0A8E, 0x0A8E }, { 0x0A92, 0x0A92 }, { 0x0AA9, 0x0AA9 },
	{ 0x0AB1, 0x0AB1 }, { 0x0AB4, 0x0AB4 }, { 0x0ABA, 0x0ABB },
	{ 0x0AC6, 0x0AC6 }, { 0x0ACA, 0x0ACA }, { 0x0ACE, 0x0ACF },
	{ 0x0AD1, 0x0ADF }, { 0x0AE4, 0x0AE5 }, { 0x0AF2, 0x0B00 },
	{ 0x0B04, 0x0B04 }, { 0x0B0D, 0x0B0E }, { 0x0B11, 0x0B12 },
	{ 0x0B29, 0x0B29 }, { 0x0B31, 0x0B31 }, { 0x0B34, 0x0B34 },
	{ 0x0B3A, 0x0B3B }, { 0x0B45, 0x0B46 }, { 0x0B49, 0x0B4A },
	{ 0x0B4E, 0x0B55 }, { 0x0B58, 0x0B5B }, { 0x0B5E, 0x0B5E },
	{ 0x0B64, 0x0B65 }, { 0x0B78, 0x0B81 }, { 0x0B84, 0x0B84 },
	{ 0x0B8B, 0x0B8D }, { 0x0B91, 0x0B91 }, { 0x0B96, 0x0B98 },
	{ 0x0B9B, 0x0B9B }, { 0x0B9D, 0x0B9D }, { 0x0BA0, 0x0BA2 },
	{ 0x0BA5, 0x0BA7 }, { 0x0BAB, 0x0BAD }, { 0x0BBA, 0x0BBD },
	{ 0x0BC3, 0x0BC5 }, { 0x0BC9, 0x0BC9 }, { 0x0BCE, 0x0BCF },
	{ 0x0BD1, 0x0BD6 }, { 0x0BD8, 0x0BE5 }, { 0x0BFB, 0x0C00 },
	{ 0x0C04, 0x0C04 }, { 0x0C0D, 0x0C0D }, { 0x0C11, 0x0C11 },
	{ 0x0C29, 0x0C29 }, { 0x0C34, 0x0C34 }, { 0x0C3A, 0x0C3C },
	{ 0x0C45, 0x0C45 }, { 0x0C49, 0x0C49 }, { 0x0C4E, 0x0C54 },
	{ 0x0C57, 0x0C57 }, { 0x0C5A, 0x0C5F }, { 0x0C64, 0x0C65 },
	{ 0x0C70, 0x0C77 }, { 0x0C80, 0x0C81 }, { 0x0C84, 0x0C84 },
	{ 0x0C8D, 0x0C8D }, { 0x0C91, 0x0C91 }, { 0x0CA9, 0x0CA9 },
	{ 0x0CB4, 0x0CB4 }, { 0x0CBA, 0x0CBB }, { 0x0CC5, 0x0CC5 },
	{ 0x0CC9, 0x0CC9 }, { 0x0CCE, 0x0CD4 }, { 0x0CD7, 0x0CDD },
	{ 0x0CDF, 0x0CDF }, { 0x0CE4, 0x0CE5 }, { 0x0CF0, 0x0CF0 },
	{ 0x0CF3, 0x0D01 }, { 0x0D04, 0x0D04 }, { 0x0D0D, 0x0D0D },
	{ 0x0D11, 0x0D11 }, { 0x0D3B, 0x0D3C }, { 0x0D45, 0x0D45 },
	{ 0x0D49, 0x0D49 }, { 0x0D4F, 0x0D56 }, { 0x0D58, 0x0D5F },
	{ 0x0D64, 0x0D65 }, { 0x0D76, 0x0D78 }, { 0x0D80, 0x0D81 },
	{ 0x0D84, 0x0D84 }, { 0x0D97, 0x0D99 }, { 0x0DB2, 0x0DB2 },
	{ 0x0DBC, 0x0DBC }, { 0x0DBE, 0x0DBF }, { 0x0DC7, 0x0DC9 },
	{ 0x0DCB, 0x0DCE }, { 0x0DD5, 0x0DD5 }, { 0x0DD7, 0x0DD7 },
	{ 0x0DE0, 0x0DF1 }, { 0x0DF5, 0x0E00 }, { 0x0E3B, 0x0E3E },
	{ 0x0E5C, 0x0E80 }, { 0x0E83, 0x0E83 }, { 0x0E85, 0x0E86 },
	{ 0x0E89, 0x0E89 }, { 0x0E8B, 0x0E8C }, { 0x0E8E, 0x0E93 },
	{ 0x0E98, 0x0E98 }, { 0x0EA0, 0x0EA0 }, { 0x0EA4, 0x0EA4 },
	{ 0x0EA6, 0x0EA6 }, { 0x0EA8, 0x0EA9 }, { 0x0EAC, 0x0EAC },
	{ 0x0EBA, 0x0EBA }, { 0x0EBE, 0x0EBF }, { 0x0EC5, 0x0EC5 },
	{ 0x0EC7, 0x0EC7 }, { 0x0ECE, 0x0ECF }, { 0x0EDA, 0x0EDB },
	{ 0x0EE0, 0x0EFF }, { 0x0F48, 0x0F48 }, { 0x0F6D, 0x0F70 },
	{ 0x0F98, 0x0F98 }, { 0x0FBD, 0x0FBD }, { 0x0FCD, 0x0FCD },
	{ 0x0FDB, 0x0FFF }, { 0x10C6, 0x10C6 }, { 0x10C8, 0x10CC },
	{ 0x10CE, 0x10CF }, { 0x115F, 0x1160 }, { 0x1249, 0x1249 },
	{ 0x124E, 0x124F }, { 0x1257, 0x1257 }, { 0x1259, 0x1259 },
	{ 0x125E, 0x125F }, { 0x1289, 0x1289 }, { 0x128E, 0x128F },
	{ 0x12B1, 0x12B1 }, { 0x12B6, 0x12B7 }, { 0x12BF, 0x12BF },
	{ 0x12C1, 0x12C1 }, { 0x12C6, 0x12C7 }, { 0x12D7, 0x12D7 },
	{ 0x1311, 0x1311 }, { 0x1316, 0x1317 }, { 0x135B, 0x135C },
	{ 0x137D, 0x137F }, { 0x139A, 0x139F }, { 0x13F5, 0x13FF },
	{ 0x169D, 0x169F }, { 0x16F1, 0x16FF }, { 0x170D, 0x170D },
	{ 0x1715, 0x171F }, { 0x1737, 0x173F }, { 0x1754, 0x175F },
	{ 0x176D, 0x176D }, { 0x1771, 0x1771 }, { 0x1774, 0x177F },
	{ 0x17B4, 0x17B5 }, { 0x17DE, 0x17DF }, { 0x17EA, 0x17EF },
	{ 0x17FA, 0x17FF }, { 0x180B, 0x180D }, { 0x180F, 0x180F },
	{ 0x181A, 0x181F }, { 0x1878, 0x187F }, { 0x18AB, 0x18AF },
	{ 0x18F6, 0x18FF }, { 0x191D, 0x191F }, { 0x192C, 0x192F },
	{ 0x193C, 0x193F }, { 0x1941, 0x1943 }, { 0x196E, 0x196F },
	{ 0x1975, 0x197F }, { 0x19AC, 0x19AF }, { 0x19CA, 0x19CF },
	{ 0x19DB, 0x19DD }, { 0x1A1C, 0x1A1D }, { 0x1A5F, 0x1A5F },
	{ 0x1A7D, 0x1A7E }, { 0x1A8A, 0x1A8F }, { 0x1A9A, 0x1A9F },
	{ 0x1AAE, 0x1AFF }, { 0x1B4C, 0x1B4F }, { 0x1B7D, 0x1B7F },
	{ 0x1BF4, 0x1BFB }, { 0x1C38, 0x1C3A }, { 0x1C4A, 0x1C4C },
	{ 0x1C80, 0x1CBF }, { 0x1CC8, 0x1CCF }, { 0x1CF7, 0x1CFF },
	{ 0x1DE7, 0x1DFB }, { 0x1F16, 0x1F17 }, { 0x1F1E, 0x1F1F },
	{ 0x1F46, 0x1F47 }, { 0x1F4E, 0x1F4F }, { 0x1F58, 0x1F58 },
	{ 0x1F5A, 0x1F5A }, { 0x1F5C, 0x1F5C }, { 0x1F5E, 0x1F5E },
	{ 0x1F7E, 0x1F7F }, { 0x1FB5, 0x1FB5 }, { 0x1FC5, 0x1FC5 },
	{ 0x1FD4, 0x1FD5 }, { 0x1FDC, 0x1FDC }, { 0x1FF0, 0x1FF1 },
	{ 0x1FF5, 0x1FF5 }, { 0x1FFF, 0x1FFF }, { 0x200B, 0x200F },
	{ 0x202A, 0x202E }, { 0x2060, 0x206F }, { 0x2072, 0x2073 },
	{ 0x208F, 0x208F }, { 0x209D, 0x209F }, { 0x20BB, 0x20CF },
	{ 0x20F1, 0x20FF }, { 0x218A, 0x218F }, { 0x23F4, 0x23FF },
	{ 0x2427, 0x243F }, { 0x244B, 0x245F }, { 0x2700, 0x2700 },
	{ 0x2B4D, 0x2B4F }, { 0x2B5A, 0x2BFF }, { 0x2C2F, 0x2C2F },
	{ 0x2C5F, 0x2C5F }, { 0x2CF4, 0x2CF8 }, { 0x2D26, 0x2D26 },
	{ 0x2D28, 0x2D2C }, { 0x2D2E, 0x2D2F }, { 0x2D68, 0x2D6E },
	{ 0x2D71, 0x2D7E }, { 0x2D97, 0x2D9F }, { 0x2DA7, 0x2DA7 },
	{ 0x2DAF, 0x2DAF }, { 0x2DB7, 0x2DB7 }, { 0x2DBF, 0x2DBF },
	{ 0x2DC7, 0x2DC7 }, { 0x2DCF, 0x2DCF }, { 0x2DD7, 0x2DD7 },
	{ 0x2DDF, 0x2DDF }, { 0x2E3C, 0x2E7F }, { 0x2E9A, 0x2E9A },
	{ 0x2EF4, 0x2EFF }, { 0x2FD6, 0x2FEF }, { 0x2FFC, 0x2FFF },
	{ 0x3040, 0x3040 }, { 0x3097, 0x3098 }, { 0x3100, 0x3104 },
	{ 0x312E, 0x3130 }, { 0x3164, 0x3164 }, { 0x318F, 0x318F },
	{ 0x31BB, 0x31BF }, { 0x31E4, 0x31EF }, { 0x321F, 0x321F },
	{ 0x32FF, 0x32FF }, { 0x4DB6, 0x4DBF }, { 0x9FCD, 0x9FFF },
	{ 0xA48D, 0xA48F }, { 0xA4C7, 0xA4CF }, { 0xA62C, 0xA63F },
	{ 0xA698, 0xA69E }, { 0xA6F8, 0xA6FF }, { 0xA78F, 0xA78F },
	{ 0xA794, 0xA79F }, { 0xA7AB, 0xA7F7 }, { 0xA82C, 0xA82F },
	{ 0xA83A, 0xA83F }, { 0xA878, 0xA87F }, { 0xA8C5, 0xA8CD },
	{ 0xA8DA, 0xA8DF }, { 0xA8FC, 0xA8FF }, { 0xA954, 0xA95E },
	{ 0xA97D, 0xA97F }, { 0xA9CE, 0xA9CE }, { 0xA9DA, 0xA9DD },
	{ 0xA9E0, 0xA9FF }, { 0xAA37, 0xAA3F }, { 0xAA4E, 0xAA4F },
	{ 0xAA5A, 0xAA5B }, { 0xAA7C, 0xAA7F }, { 0xAAC3, 0xAADA },
	{ 0xAAF7, 0xAB00 }, { 0xAB07, 0xAB08 }, { 0xAB0F, 0xAB10 },
	{ 0xAB17, 0xAB1F }, { 0xAB27, 0xAB27 }, { 0xAB2F, 0xABBF },
	{ 0xABEE, 0xABEF }, { 0xABFA, 0xABFF }, { 0xD7A4, 0xD7AF },
	{ 0xD7C7, 0xD7CA }, { 0xD7FC, 0xDFFF }, { 0xFA6E, 0xFA6F },
	{ 0xFADA, 0xFAFF }, { 0xFB07, 0xFB12 }, { 0xFB18, 0xFB1C },
	{ 0xFB37, 0xFB37 }, { 0xFB3D, 0xFB3D }, { 0xFB3F, 0xFB3F },
	{ 0xFB42, 0xFB42 }, { 0xFB45, 0xFB45 }, { 0xFBC2, 0xFBD2 },
	{ 0xFD40, 0xFD4F }, { 0xFD90, 0xFD91 }, { 0xFDC8, 0xFDEF },
	{ 0xFDFE, 0xFE0F }, { 0xFE1A, 0xFE1F }, { 0xFE27, 0xFE2F },
	{ 0xFE53, 0xFE53 }, { 0xFE67, 0xFE67 }, { 0xFE6C, 0xFE6F },
	{ 0xFE75, 0xFE75 }, { 0xFEFD, 0xFEFF }, { 0xFF00, 0xFF00 },
	{ 0xFFA0, 0xFFA0 }, { 0xFFBF, 0xFFC1 }, { 0xFFC8, 0xFFC9 },
	{ 0xFFD0, 0xFFD1 }, { 0xFFD8, 0xFFD9 }, { 0xFFDD, 0xFFDF },
	{ 0xFFE7, 0xFFE7 }, { 0xFFEF, 0xFFFB }, { 0xFFFE, 0xFFFF },
	{ 0x1000C, 0x1000C }, { 0x10027, 0x10027 }, { 0x1003B, 0x1003B },
	{ 0x1003E, 0x1003E }, { 0x1004E, 0x1004F }, { 0x1005E, 0x1007F },
	{ 0x100FB, 0x100FF }, { 0x10103, 0x10106 }, { 0x10134, 0x10136 },
	{ 0x1018B, 0x1018F }, { 0x1019C, 0x101CF }, { 0x101FE, 0x1027F },
	{ 0x1029D, 0x1029F }, { 0x102D1, 0x102FF }, { 0x1031F, 0x1031F },
	{ 0x10324, 0x1032F }, { 0x1034B, 0x1037F }, { 0x1039E, 0x1039E },
	{ 0x103C4, 0x103C7 }, { 0x103D6, 0x103FF }, { 0x1049E, 0x1049F },
	{ 0x104AA, 0x107FF }, { 0x10806, 0x10807 }, { 0x10809, 0x10809 },
	{ 0x10836, 0x10836 }, { 0x10839, 0x1083B }, { 0x1083D, 0x1083E },
	{ 0x10856, 0x10856 }, { 0x10860, 0x108FF }, { 0x1091C, 0x1091E },
	{ 0x1093A, 0x1093E }, { 0x10940, 0x1097F }, { 0x109B8, 0x109BD },
	{ 0x109C0, 0x109FF }, { 0x10A04, 0x10A04 }, { 0x10A07, 0x10A0B },
	{ 0x10A14, 0x10A14 }, { 0x10A18, 0x10A18 }, { 0x10A34, 0x10A37 },
	{ 0x10A3B, 0x10A3E }, { 0x10A48, 0x10A4F }, { 0x10A59, 0x10A5F },
	{ 0x10A80, 0x10AFF }, { 0x10B36, 0x10B38 }, { 0x10B56, 0x10B57 },
	{ 0x10B73, 0x10B77 }, { 0x10B80, 0x10BFF }, { 0x10C49, 0x10E5F },
	{ 0x10E7F, 0x10FFF }, { 0x1104E, 0x11051 }, { 0x11070, 0x1107F },
	{ 0x110BD, 0x110BD }, { 0x110C2, 0x110CF }, { 0x110E9, 0x110EF },
	{ 0x110FA, 0x110FF }, { 0x11135, 0x11135 }, { 0x11144, 0x1117F },
	{ 0x111C9, 0x111CF }, { 0x111DA, 0x1167F }, { 0x116B8, 0x116BF },
	{ 0x116CA, 0x11FFF }, { 0x1236F, 0x123FF }, { 0x12463, 0x1246F },
	{ 0x12474, 0x12FFF }, { 0x1342F, 0x167FF }, { 0x16A39, 0x16EFF },
	{ 0x16F45, 0x16F4F }, { 0x16F7F, 0x16F8E }, { 0x16FA0, 0x1AFFF },
	{ 0x1B002, 0x1CFFF }, { 0x1D0F6, 0x1D0FF }, { 0x1D127, 0x1D128 },
	{ 0x1D173, 0x1D17A }, { 0x1D1DE, 0x1D1FF }, { 0x1D246, 0x1D2FF },
	{ 0x1D357, 0x1D35F }, { 0x1D372, 0x1D3FF }, { 0x1D455, 0x1D455 },
	{ 0x1D49D, 0x1D49D }, { 0x1D4A0, 0x1D4A1 }, { 0x1D4A3, 0x1D4A4 },
	{ 0x1D4A7, 0x1D4A8 }, { 0x1D4AD, 0x1D4AD }, { 0x1D4BA, 0x1D4BA },
	{ 0x1D4BC, 0x1D4BC }, { 0x1D4C4, 0x1D4C4 }, { 0x1D506, 0x1D506 },
	{ 0x1D50B, 0x1D50C }, { 0x1D515, 0x1D515 }, { 0x1D51D, 0x1D51D },
	{ 0x1D53A, 0x1D53A }, { 0x1D53F, 0x1D53F }, { 0x1D545, 0x1D545 },
	{ 0x1D547, 0x1D549 }, { 0x1D551, 0x1D551 }, { 0x1D6A6, 0x1D6A7 },
	{ 0x1D7CC, 0x1D7CD }, { 0x1D800, 0x1EDFF }, { 0x1EE04, 0x1EE04 },
	{ 0x1EE20, 0x1EE20 }, { 0x1EE23, 0x1EE23 }, { 0x1EE25, 0x1EE26 },
	{ 0x1EE28, 0x1EE28 }, { 0x1EE33, 0x1EE33 }, { 0x1EE38, 0x1EE38 },
	{ 0x1EE3A, 0x1EE3A }, { 0x1EE3C, 0x1EE41 }, { 0x1EE43, 0x1EE46 },
	{ 0x1EE48, 0x1EE48 }, { 0x1EE4A, 0x1EE4A }, { 0x1EE4C, 0x1EE4C },
	{ 0x1EE50, 0x1EE50 }, { 0x1EE53, 0x1EE53 }, { 0x1EE55, 0x1EE56 },
	{ 0x1EE58, 0x1EE58 }, { 0x1EE5A, 0x1EE5A }, { 0x1EE5C, 0x1EE5C },
	{ 0x1EE5E, 0x1EE5E }, { 0x1EE60, 0x1EE60 }, { 0x1EE63, 0x1EE63 },
	{ 0x1EE65, 0x1EE66 }, { 0x1EE6B, 0x1EE6B }, { 0x1EE73, 0x1EE73 },
	{ 0x1EE78, 0x1EE78 }, { 0x1EE7D, 0x1EE7D }, { 0x1EE7F, 0x1EE7F },
	{ 0x1EE8A, 0x1EE8A }, { 0x1EE9C, 0x1EEA0 }, { 0x1EEA4, 0x1EEA4 },
	{ 0x1EEAA, 0x1EEAA }, { 0x1EEBC, 0x1EEEF }, { 0x1EEF2, 0x1EFFF },
	{ 0x1F02C, 0x1F02F }, { 0x1F094, 0x1F09F }, { 0x1F0AF, 0x1F0B0 },
	{ 0x1F0BF, 0x1F0C0 }, { 0x1F0D0, 0x1F0D0 }, { 0x1F0E0, 0x1F0FF },
	{ 0x1F10B, 0x1F10F }, { 0x1F12F, 0x1F12F }, { 0x1F16C, 0x1F16F },
	{ 0x1F19B, 0x1F1E5 }, { 0x1F203, 0x1F20F }, { 0x1F23B, 0x1F23F },
	{ 0x1F249, 0x1F24F }, { 0x1F252, 0x1F2FF }, { 0x1F321, 0x1F32F },
	{ 0x1F336, 0x1F336 }, { 0x1F37D, 0x1F37F }, { 0x1F394, 0x1F39F },
	{ 0x1F3C5, 0x1F3C5 }, { 0x1F3CB, 0x1F3DF }, { 0x1F3F1, 0x1F3FF },
	{ 0x1F43F, 0x1F43F }, { 0x1F441, 0x1F441 }, { 0x1F4F8, 0x1F4F8 },
	{ 0x1F4FD, 0x1F4FF }, { 0x1F53E, 0x1F53F }, { 0x1F544, 0x1F54F },
	{ 0x1F568, 0x1F5FA }, { 0x1F641, 0x1F644 }, { 0x1F650, 0x1F67F },
	{ 0x1F6C6, 0x1F6FF }, { 0x1F774, 0x1FFFF }, { 0x2A6D7, 0x2A6FF },
	{ 0x2B735, 0x2B73F }, { 0x2B81E, 0x2F7FF }, { 0x2FA1E, 0xF0000 },
	{ 0xFFFFE, 0xFFFFF }, { 0x10FFFE, 0x10FFFF }
};
static const int nonprintable_ranges_count = sizeof (nonprintable_ranges) / sizeof (nonprintable_ranges[0]);

R_API int r_utf8_decode (const ut8 *ptr, RRune *ch) {
	if (ptr[0] < 0x80) {
		*ch = (ut32)ptr[0];
		return 1;
	}
	else if ((ptr[0]&0xe0) == 0xc0) {
		*ch = (ptr[0] & 0x1f) << 6 | (ptr[1] & 0x3f);
		return 2;
	}
	else if ((ptr[0]&0xf0) == 0xe0) {
		*ch = (ptr[0] & 0xf) << 12 | (ptr[1] & 0x3f) << 6 | (ptr[2] & 0x3f);
		return 3;
	}
	else {
		*ch = (ut32)ptr[0];
		return 1;
	}
}

R_API int r_isprint (const RRune c) {
	int low, hi, mid;

	low = 0;
	hi = nonprintable_ranges_count;

	do {
		mid = (low + hi) >> 1;
		if (c >= nonprintable_ranges[mid].from && c <= nonprintable_ranges[mid].to)
			return R_FALSE;
		if (c > nonprintable_ranges[mid].to)
			low = mid + 1;
		if (c < nonprintable_ranges[mid].from)
			hi = mid - 1;
	} while (low <= hi);

	return R_TRUE;
}

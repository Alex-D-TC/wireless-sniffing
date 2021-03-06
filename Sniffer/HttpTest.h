#ifndef _HTTP_TEST_H_
#define _HTTP_TEST_H_

#include <pcap.h>

char gHttpTestPacket[] =
{
'\x00', '\x00', '\xcd', '\x38', '\x25', '\x7c', '\xa0', '\xc5', '\x89', '\xbf', '\xdb', '\xd7', '\x08', '\x00', '\x45', '\x00', '\x02', '\x58', '\x93',
'\xfe', '\x40', '\x00', '\x80', '\x06', '\xb7', '\x1e', '\x0a', '\x98', '\x00', '\xc8', '\xc1', '\x00', '\xe1', '\x22', '\xf3', '\x0c', '\x00', '\x50',
'\xed', '\x01', '\x9e', '\x97', '\xd7', '\x9a', '\xbe', '\x06', '\x50', '\x18', '\x01', '\x00', '\x4c', '\x76', '\x00', '\x00', '\x47', '\x45', '\x54',
'\x20', '\x2f', '\x7e', '\x66', '\x6f', '\x72', '\x65', '\x73', '\x74', '\x2f', '\x20', '\x48', '\x54', '\x54', '\x50', '\x2f', '\x31', '\x2e', '\x31',
'\x0d', '\x0a', '\x48', '\x6f', '\x73', '\x74', '\x3a', '\x20', '\x77', '\x77', '\x77', '\x2e', '\x63', '\x73', '\x2e', '\x75', '\x62', '\x62', '\x63',
'\x6c', '\x75', '\x6a', '\x2e', '\x72', '\x6f', '\x0d', '\x0a', '\x43', '\x6f', '\x6e', '\x6e', '\x65', '\x63', '\x74', '\x69', '\x6f', '\x6e', '\x3a',
'\x20', '\x6b', '\x65', '\x65', '\x70', '\x2d', '\x61', '\x6c', '\x69', '\x76', '\x65', '\x0d', '\x0a', '\x43', '\x61', '\x63', '\x68', '\x65', '\x2d',
'\x43', '\x6f', '\x6e', '\x74', '\x72', '\x6f', '\x6c', '\x3a', '\x20', '\x6d', '\x61', '\x78', '\x2d', '\x61', '\x67', '\x65', '\x3d', '\x30', '\x0d',
'\x0a', '\x55', '\x70', '\x67', '\x72', '\x61', '\x64', '\x65', '\x2d', '\x49', '\x6e', '\x73', '\x65', '\x63', '\x75', '\x72', '\x65', '\x2d', '\x52',
'\x65', '\x71', '\x75', '\x65', '\x73', '\x74', '\x73', '\x3a', '\x20', '\x31', '\x0d', '\x0a', '\x55', '\x73', '\x65', '\x72', '\x2d', '\x41', '\x67',
'\x65', '\x6e', '\x74', '\x3a', '\x20', '\x4d', '\x6f', '\x7a', '\x69', '\x6c', '\x6c', '\x61', '\x2f', '\x35', '\x2e', '\x30', '\x20', '\x28', '\x57',
'\x69', '\x6e', '\x64', '\x6f', '\x77', '\x73', '\x20', '\x4e', '\x54', '\x20', '\x31', '\x30', '\x2e', '\x30', '\x3b', '\x20', '\x57', '\x69', '\x6e',
'\x36', '\x34', '\x3b', '\x20', '\x78', '\x36', '\x34', '\x29', '\x20', '\x41', '\x70', '\x70', '\x6c', '\x65', '\x57', '\x65', '\x62', '\x4b', '\x69',
'\x74', '\x2f', '\x35', '\x33', '\x37', '\x2e', '\x33', '\x36', '\x20', '\x28', '\x4b', '\x48', '\x54', '\x4d', '\x4c', '\x2c', '\x20', '\x6c', '\x69',
'\x6b', '\x65', '\x20', '\x47', '\x65', '\x63', '\x6b', '\x6f', '\x29', '\x20', '\x43', '\x68', '\x72', '\x6f', '\x6d', '\x65', '\x2f', '\x37', '\x38',
'\x2e', '\x30', '\x2e', '\x33', '\x39', '\x30', '\x34', '\x2e', '\x31', '\x30', '\x38', '\x20', '\x53', '\x61', '\x66', '\x61', '\x72', '\x69', '\x2f',
'\x35', '\x33', '\x37', '\x2e', '\x33', '\x36', '\x20', '\x4f', '\x50', '\x52', '\x2f', '\x36', '\x35', '\x2e', '\x30', '\x2e', '\x33', '\x34', '\x36',
'\x37', '\x2e', '\x37', '\x38', '\x0d', '\x0a', '\x41', '\x63', '\x63', '\x65', '\x70', '\x74', '\x3a', '\x20', '\x74', '\x65', '\x78', '\x74', '\x2f',
'\x68', '\x74', '\x6d', '\x6c', '\x2c', '\x61', '\x70', '\x70', '\x6c', '\x69', '\x63', '\x61', '\x74', '\x69', '\x6f', '\x6e', '\x2f', '\x78', '\x68',
'\x74', '\x6d', '\x6c', '\x2b', '\x78', '\x6d', '\x6c', '\x2c', '\x61', '\x70', '\x70', '\x6c', '\x69', '\x63', '\x61', '\x74', '\x69', '\x6f', '\x6e',
'\x2f', '\x78', '\x6d', '\x6c', '\x3b', '\x71', '\x3d', '\x30', '\x2e', '\x39', '\x2c', '\x69', '\x6d', '\x61', '\x67', '\x65', '\x2f', '\x77', '\x65',
'\x62', '\x70', '\x2c', '\x69', '\x6d', '\x61', '\x67', '\x65', '\x2f', '\x61', '\x70', '\x6e', '\x67', '\x2c', '\x2a', '\x2f', '\x2a', '\x3b', '\x71',
'\x3d', '\x30', '\x2e', '\x38', '\x2c', '\x61', '\x70', '\x70', '\x6c', '\x69', '\x63', '\x61', '\x74', '\x69', '\x6f', '\x6e', '\x2f', '\x73', '\x69',
'\x67', '\x6e', '\x65', '\x64', '\x2d', '\x65', '\x78', '\x63', '\x68', '\x61', '\x6e', '\x67', '\x65', '\x3b', '\x76', '\x3d', '\x62', '\x33', '\x0d',
'\x0a', '\x41', '\x63', '\x63', '\x65', '\x70', '\x74', '\x2d', '\x45', '\x6e', '\x63', '\x6f', '\x64', '\x69', '\x6e', '\x67', '\x3a', '\x20', '\x67',
'\x7a', '\x69', '\x70', '\x2c', '\x20', '\x64', '\x65', '\x66', '\x6c', '\x61', '\x74', '\x65', '\x0d', '\x0a', '\x41', '\x63', '\x63', '\x65', '\x70',
'\x74', '\x2d', '\x4c', '\x61', '\x6e', '\x67', '\x75', '\x61', '\x67', '\x65', '\x3a', '\x20', '\x65', '\x6e', '\x2d', '\x47', '\x42', '\x2c', '\x65',
'\x6e', '\x2d', '\x55', '\x53', '\x3b', '\x71', '\x3d', '\x30', '\x2e', '\x39', '\x2c', '\x65', '\x6e', '\x3b', '\x71', '\x3d', '\x30', '\x2e', '\x38',
'\x0d', '\x0a', '\x43', '\x6f', '\x6f', '\x6b', '\x69', '\x65', '\x3a', '\x20', '\x5f', '\x67', '\x61', '\x3d', '\x47', '\x41', '\x31', '\x2e', '\x32',
'\x2e', '\x31', '\x34', '\x37', '\x34', '\x36', '\x33', '\x30', '\x36', '\x33', '\x2e', '\x31', '\x35', '\x37', '\x35', '\x31', '\x39', '\x31', '\x38',
'\x30', '\x37', '\x3b', '\x20', '\x50', '\x48', '\x50', '\x53', '\x45', '\x53', '\x53', '\x49', '\x44', '\x3d', '\x64', '\x69', '\x35', '\x72', '\x31',
'\x65', '\x69', '\x6d', '\x6d', '\x75', '\x74', '\x66', '\x6b', '\x65', '\x62', '\x72', '\x34', '\x74', '\x73', '\x72', '\x30', '\x37', '\x6a', '\x67',
'\x62', '\x36', '\x0d', '\x0a', '\x0d', '\x0a'
};

struct timeval gHttpTestTime { 0 };
pcap_pkthdr gHttpTestPcapHeader{ gHttpTestTime, sizeof(gHttpTestPacket), sizeof(gHttpTestPacket) };


#endif // _HTTP_TEST_H_

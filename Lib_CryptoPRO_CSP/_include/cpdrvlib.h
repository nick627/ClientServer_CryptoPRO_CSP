/*
 * Copyright(C) 2000-2006 Проект ИОК
 *
 * Этот файл содержит информацию, являющуюся
 * собственностью компании Крипто Про.
 *
 * Любая часть этого файла не может быть скопирована,
 * исправлена, переведена на другие языки,
 * локализована или модифицирована любым способом,
 * откомпилирована, передана по сети с или на
 * любую компьютерную систему без предвoiарительного
 * заключения соглашения с компанией Крипто Про.
 */

/*!
 * \file $RCSfile$
 * \version $Revision: 126987 $
 * \date $Date:: 2015-09-08 16:51:58 +0300#$
 * \author $Author: pav $
 *
 * \brief Внешние определения для работы с cpdrvlib
 *
 * Содержит определения IOCTL, поддерживаемых cpdrvlib, и имена создаваемых
 * этим драйвером устройств.
 */
#ifndef _CPDRVLIB_H_INCLUDED
#define _CPDRVLIB_H_INCLUDED

#ifndef CTL_CODE
#include <winioctl.h>
#endif // CTL_CODE

#define IOCTL_GETCPCCREATEPROVIDER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0810, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GETCPCGETDEFAULTCONFIG CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0811, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GETCPCINITMEMORYLF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0812, METHOD_BUFFERED, FILE_READ_ACCESS)

#define CPDRVLIB_NAME L"cpdrvlib"
#define CPDRVLIB_NT_DEVICE_NAME L"\\Device\\" CPDRVLIB_NAME
#define CPDRVLIB_DOS_DEVICE_NAME L"\\DosDevices\\Global\\" CPDRVLIB_NAME

#define CPKSP_NAME L"CPKSP"
#define CPKSP_NT_DEVICE_NAME L"\\Device\\" CPKSP_NAME
#define CPKSP_DOS_DEVICE_NAME L"\\DosDevices\\Global\\" CPKSP_NAME


#endif // _CPDRVLIB_H_INCLUDED

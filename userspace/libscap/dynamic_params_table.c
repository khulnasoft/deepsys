/*
Copyright (C) 2013-2014 KhulnaSoft, Ltd.

This file is part of deepsys.

deepsys is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

deepsys is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with deepsys.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../common/deepsys_types.h"
#include "../../driver/ppm_events_public.h"

const struct ppm_param_info ptrace_dynamic_param[PPM_PTRACE_IDX_MAX] = {
	{{0}, PT_UINT64, PF_HEX},
	{{0}, PT_SIGTYPE, PF_DEC},
};

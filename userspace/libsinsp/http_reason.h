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

#pragma once

#include <string>
#include <map>

class http_reason
{
public:
	static std::string get(int status);

private:
	static const std::map<int, std::string> m_http_reason;
};

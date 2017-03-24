import zipfile
import os
import shutil
import xml.etree.ElementTree as ET
import re
from xml.etree.ElementTree import tostring

class ExcelToolKit:
    """
    Toolkit for get and set value from a Xlsx file
    """

    def __init__(self, path_to_zip_file, directory_to_extract_to="tmp_dir/"):
        """
        Init the toolkit take in parameter the path to the zip file
        and a path to a tmp dir in order to put all the extract file during the process
        """
        self.path_to_zip_file = path_to_zip_file
        if directory_to_extract_to[len(directory_to_extract_to)-1] != "/":
            directory_to_extract_to += "/"
        self.directory_to_extract_to = directory_to_extract_to
        self.current_sheet = None
        self.current_root = None
        self.current_sheet_number = None

    def unzip_file(self):
        """
        Unzip file which is in path_to_zip_file into the directory represent by directory_to_extract_to
        path_to_zip_file = os.path.dirname(os.path.abspath(__file__)) + "/file1.xlsx"
        directory_to_extract_to = os.path.dirname(os.path.abspath(__file__)) + "/test_save/"
        and open the shared strings
        """
        if zipfile.is_zipfile(self.path_to_zip_file):
            zip_ref = zipfile.ZipFile(self.path_to_zip_file, 'r')
            zip_ref.extractall(self.directory_to_extract_to)
            zip_ref.close()
            self.open_shared_strings()

    def zip_file(self, zip_name):
        """
        Save the shared strings then
        zip all the content of directory_to_zip directory into a zip_name file
        """
        self.save_shared_strings()

        zf = zipfile.ZipFile(zip_name, mode='w')
        for dirname, subdirs, files in os.walk(self.directory_to_extract_to):
            for filename in files:
                path = os.path.join(dirname, filename)
                path_without_directory = path[len(self.directory_to_extract_to):]
                zf.write(os.path.join(dirname, filename), path_without_directory)
        zf.close()

        # Delete tmp folder content
        for the_file in os.listdir(self.directory_to_extract_to):
            file_path = os.path.join(self.directory_to_extract_to, the_file)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path): shutil.rmtree(file_path)
            except Exception as e:
                print(e)

    def save_sheet(self):
        """
        Save the current data sheet
        """
        data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        data_sheet_idx = 0
        for idx, child in enumerate(self.current_root):
            if child.tag[child.tag.index('}') + 1:] == "sheetData":
                data_sheet_idx = idx
                break
        self.current_root[data_sheet_idx] = self.current_sheet
        data += tostring(self.current_root).replace("ns0:", "")
        data = data.replace(":ns0", "")
        data = data.replace("ns1:", "").replace(":ns1", "1")
        data = data.replace("ns2:", "").replace(":ns2", "2")
        data = data.replace("ns3:", "").replace(":ns3", "3")
        data = data.replace("ns4:", "").replace(":ns4", "4")
        data = data.replace("ns5:", "").replace(":ns5", "5")
        data = data.replace("ns6:", "").replace(":ns6", "6")
        with open(self.directory_to_extract_to + "xl/worksheets/sheet" + str(self.current_sheet_number) + ".xml", "w") as text_file:
            text_file.write(data)

    def get_child_by_tag(self, element, child_name):
        """
        return an array containing every element child with the tag child_name
        """
        data = []
        for child in element:
            if "}" in child.tag:
                if child.tag[child.tag.index('}') + 1:] == child_name:
                    data.append(child)
            else:
                if child.tag == child_name:
                    data.append(child)
        return data

    def select_sheet(self, number):
        """
        return the root corresponding to the sheet with the parameter number
        """
        tree = ET.parse(self.directory_to_extract_to + "xl/worksheets/sheet" + str(number) + ".xml")
        self.current_root = tree.getroot()
        self.current_sheet_number = number
        self.current_sheet = self.get_child_by_tag(tree.getroot(), "sheetData")[0]

    def create_basic_row(self, line):
        new_row = ET.Element("row")
        new_row.set("customFormat", "false")
        new_row.set("customHeight", "false")
        new_row.set("hidden", "false")
        new_row.set("outlineLevel", "0")
        new_row.set("collapsed", "false")
        new_row.set("ht", "12.8")
        new_row.set("r", str(line))
        return new_row

    def open_shared_strings(self):
        """
        set the self.shared_strings element
        """
        tree = ET.parse(self.directory_to_extract_to + "xl/sharedStrings.xml")
        self.shared_strings = tree.getroot()

    def save_shared_strings(self):
        """
        save the self.shared_strings element
        """
        data = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        data += tostring(self.shared_strings).replace("ns0:", "")
        data = data.replace(":ns0", "")
        data = data.replace("ns1:", "").replace(":ns1", "1")
        data = data.replace("ns2:", "").replace(":ns2", "2")
        with open(self.directory_to_extract_to + "xl/sharedStrings.xml", "w") as text_file:
            text_file.write(data)

    def get_string_by_number(self, number):
        """
        return the string at the position number in the shared strings list
        """
        return self.shared_strings[number][0].text

    def get_string_idx(self, value, add_option=True):
        """
        return the index of a string if the string is not in the list
        then it add it at the end and return the index
        If you don't want to add it then send false into the second parameter
        """
        value = str(value)
        value_idx = None
        for idx, si in enumerate(self.shared_strings):
            if "}" in si[0].tag:
                if si[0].tag[si[0].tag.index('}') + 1:] == "t":
                    if si[0].text == value:
                        value_idx = idx
            else:
                if si[0].tag == "t":
                    if si[0].text == value:
                        value_idx = idx

        if (value_idx is None) and (add_option is True):
            new_si = ET.Element("si")
            new_value = ET.Element("t")
            new_value.text = value
            new_si.append(new_value)
            self.shared_strings.append(new_si)
            value_idx = len(self.shared_strings) - 1
        return value_idx

    def create_basic_col(self, col, data):
        new_col = ET.Element("c")
        new_col.set("r", col)
        new_col.set("s", "0")
        new_value = ET.Element("v")
        if isinstance(data, int) or isinstance(data, float):
            new_col.set("t", "n")
            new_value.text = str(data)
        else:
            new_col.set("t", "s")
            new_value.text = str(self.get_string_idx(data))
        new_col.append(new_value)
        return new_col

    def set_value(self, line, col, value):
        """
        set the value of a case in the sheet_data_node
        with the coordinate (line,col) at the value (value)
        """
        if self.current_sheet is None:
            return False
        if isinstance(col, int):
            col = self.colnum_string(col)

        sheet_data_node = self.current_sheet
        # Search for the Row & create it if not exist
        rows = self.get_child_by_tag(sheet_data_node, "row")
        superior_row = None
        search_row = None
        for idx, row in enumerate(rows):
            if int(row.attrib["r"]) == int(line):
                search_row = idx
                break
            if int(row.attrib["r"]) > int(line):
                superior_row = idx
                break
        if search_row is None:
            new_row = self.create_basic_row(line)
            if superior_row is not None:
                self.current_sheet.insert(superior_row, new_row)
                search_row = self.current_sheet[superior_row]
                search_row_idx = superior_row
            else:
                self.current_sheet.append(new_row)
                search_row = self.current_sheet[len(rows)]
                search_row_idx = len(rows)
        else:
            search_row_idx = search_row
            search_row = self.current_sheet[search_row_idx]
        # Search for the col and set value & create it if not exist
        search_col = None
        superior_col = None
        columns = self.get_child_by_tag(search_row, "c")
        for idx, column in enumerate(columns):
            if column.attrib["r"] == (col+str(line)):
                search_col = idx
                break
            if self.colNameToNum(column.attrib["r"][:column.attrib["r"].index(str(line))]) > self.colNameToNum(col):
                superior_col = idx
                break

        if search_col is None:
            new_col = self.create_basic_col(col+str(line), value)
            if superior_col is not None:
                self.current_sheet[search_row_idx].insert(superior_col, new_col)
            else:
                self.current_sheet[search_row_idx].append(new_col)
        else:
            self.current_sheet[search_row_idx][search_col] = self.create_basic_col(col+str(line), value)
        return True

    def num(self, s):
        try:
            return int(s)
        except ValueError:
            return float(s)

    def get_value(self, line, col):
        """
        return the value in the data sheet at the coordinate (line,col)
        """
        line = int(line)
        if self.current_sheet is None:
            return False
        if isinstance(col, int):
            col = self.colnum_string(col)

        sheet_data_node = self.current_sheet
        rows = self.get_child_by_tag(sheet_data_node, "row")
        data = None
        row_to_search = None
        for row in rows:
            if int(row.attrib["r"]) == line:
                row_to_search = row
                break
        if row_to_search is not None:
            columns = self.get_child_by_tag(row_to_search, "c")
            for column in columns:
                if column.attrib["r"] == (col+str(line)):
                    data = column
        if data is not None:
            if len(data.attrib) > 2:
                if data.attrib["t"] == "s":
                    data = self.get_string_by_number(int(self.get_child_by_tag(data, "v")[0].text))
                elif data.attrib["t"] == "n":
                    data = self.num(self.get_child_by_tag(data, "v")[0].text)
                elif data.attrib["t"] == "str":
                    data = self.get_child_by_tag(data, "v")[0].text
        return data

    def get_coord_from_value(self, value):
        """
        Return the coord of the case containing the value sent
        like this s(tr) col+line
        """
        data = []
        if not isinstance(value, int) and not isinstance(value, float):
            value_idx = self.get_string_idx(str(value), False)
        for idx_row, row in enumerate(self.current_sheet):
            for idx_col, column in enumerate(row):
                if len(column):
                    for elem in column:
                        if "}" in elem.tag:
                            if elem.tag[elem.tag.index('}') + 1:] == "v":
                                if column.attrib["t"] == "n" or column.attrib["t"] == "str":
                                    if str(elem.text) == str(value):
                                        data.append(column.attrib["r"])
                                elif column.attrib["t"] == "s":
                                    if str(elem.text) == str(value_idx):
                                        data.append(column.attrib["r"])
                        else:
                            if elem.tag == "v":
                                if column.attrib["t"] == "n":
                                    if str(elem.text) == str(value):
                                        data.append(column.attrib["r"])
                                elif column.attrib["t"] == "s":
                                    if str(elem.text) == str(value_idx):
                                        data.append(column.attrib["r"])
        return data

    def colnum_string(self, n):
        """
        convert column number to column letter
        """
        div = n
        string = ""
        while div > 0:
            module = (div - 1) % 26
            string = chr(65 + module) + string
            div = int((div - module) / 26)
        return string

    def last_column_in_line(self, line):
        """
        return the last column letter in the line given
        """
        for row in self.current_sheet:
            if row.attrib["r"] == str(line):
                col_attrib = row[len(row)-1].attrib["r"]
                ip_source_line = re.search(r'\d+', col_attrib).group()
                return col_attrib[:col_attrib.index(ip_source_line)]
        return None

    def last_line_in_column(self, column):
        """
        return the last line number in the column given
        """
        if isinstance(column, int):
            column = self.colnum_string(column)
        last_line = None
        for idx, row in enumerate(self.current_sheet):
            for col in row:
                if col.attrib["r"] == column+row.attrib["r"]:
                        last_line = row.attrib["r"]
        if isinstance(last_line, str):
            last_line = int(last_line)
        return last_line

    def colNameToNum(self, name):
        pow = 1
        colNum = 0
        for letter in name[::-1]:
            colNum += (int(letter, 36) - 9) * pow
            pow *= 26
        return colNum
"""
ExcelToolKit((string)path_to_file, (optional string) path_to_tmp_dir)
unzip_file()
select_sheet((int)Number_of_your_sheet_to_select)
get_value((int)line, (string)col)
set_value((int) line, (string)col)
save_sheet()
zip_file()
colnum_string(number)
"""

#EXAMPLE
"""
toolkit = ExcelToolkit(os.path.dirname(os.path.abspath(__file__)) + "/file1.xlsx")
toolkit.unzip_file()
toolkit.select_sheet(1)
print toolkit.get_value(2, "A")
toolkit.set_value(2, "A", "test")
print toolkit.get_value(2, "A")
for coord in toolkit.get_coord_from_value("Test-21"):
    print coord
toolkit.save_sheet()
toolkit.zip_file(os.path.dirname(os.path.abspath(__file__)) + "/final_file.xlsx")
"""


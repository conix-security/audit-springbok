from SpringBase.Ip import Ip
from SpringBase.Operator import Operator

class ReduceRule:

    def reduce_rule(self, rulelist):
        """
        Merge all the rules which can be merge in the rulelist
        """
        rulelist_to_reduce = self.detect_reduce_rule(rulelist)
        while rulelist_to_reduce:
            items_to_delete = {}
            for rule_to_reduce in rulelist_to_reduce:
                rule = self.merge_two_rules(rulelist[rule_to_reduce[0]], rulelist[rule_to_reduce[1]])
                items_to_delete[rule_to_reduce[0]] = ""
                items_to_delete[rule_to_reduce[1]] = ""
                rulelist.append(rule)
            rulelist = [i for j, i in enumerate(rulelist) if j not in items_to_delete]
            rulelist_to_reduce = self.detect_reduce_rule(rulelist)
        return rulelist

    def detect_reduce_rule(self, rulelist):
        """
        Detect in a list of rules if there is any couple of rule
        which can be merged
        """
        rulelist_to_reduce = []
        rulelist_use = {}
        for idx, rule in enumerate(rulelist):
            if idx in rulelist_use:
                continue
            for idx_tmp, tmp_rule in enumerate(rulelist):
                if idx_tmp in rulelist_use:
                    continue
                if rule != tmp_rule and self.is_action_equals(rule.action, tmp_rule.action):
                    count = 0

                    if self.is_operator_list_equals(rule.ip_source, tmp_rule.ip_source):
                        count += 1
                    if self.is_operator_list_equals(rule.port_source, tmp_rule.port_source):
                        count += 1
                    if self.is_operator_list_equals(rule.ip_dest, tmp_rule.ip_dest):
                        count += 1
                    if self.is_operator_list_equals(rule.port_dest, tmp_rule.port_dest):
                        count += 1
                    if self.is_operator_list_equals(rule.protocol, tmp_rule.protocol):
                        count += 1
                    if count > 3:
                        rulelist_use[idx] = ""
                        rulelist_use[idx_tmp] = ""
                        rulelist_to_reduce.append([idx, idx_tmp])
                        break
        return rulelist_to_reduce

    def merge_two_rules(self, rule1, rule2):
        """
        merge two rules in only one
        Each rule should have at least 3 same items in the following list and the same action:
        ip_source, port_source, ip_dest, port_dest
        """
        if self.is_action_equals(rule1.action, rule2.action):

            ip_source = self.is_operator_list_equals(rule1.ip_source, rule2.ip_source)
            port_source = self.is_operator_list_equals(rule1.port_source, rule2.port_source)
            ip_dest = self.is_operator_list_equals(rule1.ip_dest, rule2.ip_dest)
            port_dest = self.is_operator_list_equals(rule1.port_dest, rule2.port_dest)
            action = self.is_action_equals(rule1.action, rule2.action)
            protocol = self.is_operator_list_equals(rule1.protocol, rule2.protocol)
            if action:
                if not ip_source:
                    rule1.ip_source = self.merge_two_operator_list(rule1.ip_source, rule2.ip_source)
                elif not port_source:
                    rule1.port_source = self.merge_two_operator_list(rule1.port_source, rule2.port_source)
                elif not ip_dest:
                    rule1.ip_dest = self.merge_two_operator_list(rule1.ip_dest, rule2.ip_dest)
                elif not port_dest:
                    rule1.port_dest = self.merge_two_operator_list(rule1.port_dest, rule2.port_dest)
                elif not protocol:
                    rule1.protocol = self.merge_two_operator_list(rule1.protocol, rule2.protocol)
        return rule1

    def merge_two_operator_list(self, operators1, operators2):
        """
        Merge two operators list in a unique one
        """
        final_list = []
        if (not len(operators1)) or (not len(operators2)):
            return final_list
        result_list = self.compare_operator_list(operators1, operators2)
        for item in result_list:
            if item[1] == 1:
                final_list.append(operators1[item[0]])
            if item[1] == 2:
                final_list.append(operators2[item[0]])
        if isinstance(final_list[0].v1, Ip):
            final_list = self.check_ip_merge(final_list)
        return final_list

    def check_ip_merge(self, final_list):
        """
        Change each mask of ip into Range of IP
        Then detect every possible link between range/ip
        and merge the possible ip/range
        """
        to_delete = {}
        for idx, ip_check1 in enumerate(final_list):
            # Value of ip 255.255.255.255 in int is 4294967295
            if ip_check1.v1.mask != 4294967295:
                tmp_val = 4294967295
                ip_min_check = ip_check1.v1.ip & ip_check1.v1.mask
                tmp_val = tmp_val ^ ip_check1.v1.mask
                ip_max_check = ip_check1.v1.ip | tmp_val
                ip_check1 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                final_list[idx] = ip_check1
            for idx2, ip_check2 in enumerate(final_list):
                if idx2 in to_delete or idx == idx2:
                    continue
                if ip_check2.v1.mask != 4294967295:
                    tmp_val = 4294967295
                    ip_min_check = ip_check2.v1.ip & ip_check2.v1.mask
                    tmp_val = tmp_val ^ ip_check2.v1.mask
                    ip_max_check = ip_check2.v1.ip | tmp_val
                    ip_check2 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                    final_list[idx2] = ip_check2
                if ip_check1.operator == "EQ" and ip_check2.operator == "EQ":
                    val_ip1 = ip_check1.v1.ip & ip_check2.v1.mask
                    val_ip2 = ip_check2.v1.ip & ip_check2.v1.mask
                    if val_ip1 == val_ip2:
                        to_delete[idx] = ""
                else:
                    ip_min = None
                    ip_max = None
                    ip_to_compare_min = None
                    ip_to_compare_max = None
                    if ip_check1.operator == "RANGE" and ip_check2.operator == "RANGE":
                        ip_min = ip_check1.v1
                        ip_max = ip_check1.v2
                        ip_to_compare_min = ip_check2.v1
                        ip_to_compare_max = ip_check2.v2
                    elif ip_check1.operator == "RANGE":
                        ip_min = ip_check1.v1
                        ip_max = ip_check1.v2
                        ip_to_compare_min = ip_check2.v1
                    elif ip_check2.operator == "RANGE":
                        ip_min = ip_check2.v1
                        ip_max = ip_check2.v2
                        ip_to_compare_min = ip_check1.v1
                    result = self.merge_ip_range(ip_min, ip_max, ip_to_compare_min, ip_to_compare_max)
                    if result:
                        if idx > idx2:
                            final_list[idx] = result
                            to_delete[idx2] = ""
                        else:
                            final_list[idx2] = result
                            to_delete[idx] = ""

        final_list = [i for j, i in enumerate(final_list) if j not in to_delete]
        return final_list

    def merge_ip_range(self, ip_min, ip_max, ip_to_compare_min, ip_to_compare_max):
        """
        The function merge 2 range or 1 range and one ip
        If the merge is possible return the new operator otherwise return nothing
        ip_min/ip_max are the ip for the first range
        ip_to_compare_min/ip_to_compare_max is the second range
        to compare to an ip just send a non value for ip_to_compare_max
        """
        ip1 = None
        ip2 = None
        operator = None
        if (not ip_to_compare_max) and (ip_min <= ip_to_compare_min <= ip_max):
            ip1 = Ip(ip_min.ip)
            ip2 = Ip(ip_max.ip)
        elif ip_to_compare_max:
            if ip_min.ip <= ip_to_compare_min.ip <= ip_max.ip:
                ip1 = Ip(ip_min.ip)
                ip2 = Ip(ip_max.ip) if ip_max.ip > ip_to_compare_max.ip else Ip(ip_to_compare_max.ip)
            elif ip_min.ip <= ip_to_compare_max.ip <= ip_max.ip:
                ip1 = Ip(ip_to_compare_min.ip)
                ip2 = Ip(ip_max.ip)
            elif ip_to_compare_min.ip < ip_min.ip and ip_to_compare_max.ip > ip_max.ip:
                ip1 = Ip(ip_to_compare_min.ip)
                ip2 = Ip(ip_to_compare_max.ip)
        if ip1 and ip2:
            operator = Operator("RANGE", ip1, ip2)
        return operator

    def compare_operator_list(self, operators1, operators2):
        """
        Compare two operator list and return a list
        The return list contains every component to select in order
        to create a unique operators
        """
        operators1_seria = [i.seria_compare() for i in operators1]
        operators2_seria = [i.seria_compare() for i in operators2]
        comparator_list = set(operators1_seria + operators2_seria)
        result_list = []
        for item in comparator_list:
            found = False
            for i, j in enumerate(operators1_seria):
                if j == item:
                    result_list.append([i, 1])
                    found = True
                    break
            if found:
                continue
            for i, j in enumerate(operators2_seria):
                if j == item:
                    result_list.append([i, 2])
                    break
        return result_list

    def is_operator_list_equals(self, operators1, operators2):
        """
        Return true if operators list are equals return false otherwise
        """
        check = True
        operators1_seria = [i.seria_compare() for i in operators1]
        operators2_seria = [i.seria_compare() for i in operators2]
        comparator_list = set(operators1_seria + operators2_seria)
        len_comparator = len(comparator_list)
        if (len_comparator != len(operators1_seria)) or (len_comparator != len(operators2_seria)):
            check = False
        return check

    def is_action_equals(self, action1, action2):
        return (action1.chain == action2.chain) and (action1.goto == action2.goto)
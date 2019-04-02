import time



data_path = "path-to-the-result-of-type1,2-analysis"

result = open("path-to-the-result-file", 'w')

with open(data_path) as f:
    content = f.readlines()
btc_hijacking_list = [x.strip() for x in content]

timestamp_set = set()


start = int(btc_hijacking_list[0].split('|')[1])
end = int(btc_hijacking_list[len(btc_hijacking_list)-1].split('|')[1])
current = 0

for timestamp in range(start, end+1) :
	cnt = 0
	type_0_cnt = 0
	type_1_cnt = 0
	attacker_AS_dict = dict()
	checking_index = current
	current = end + 1

	prefix_set = set()
	while True :
		i = btc_hijacking_list[checking_index]
		
		if(i.split('|')[5] in prefix_set) :
			checking_index += 1
			if(checking_index == len(btc_hijacking_list)) : break
			continue
		prefix_set.add(i.split('|')[5])

		new_timestamp = int(i.split('|')[1])
		hijacking_type = i.split(' ')[len(i.split(' '))-1]
		if(new_timestamp > timestamp and current > checking_index) :
			current = checking_index
		if(new_timestamp-timestamp > 600) : break

		cnt += 1
		
		AS_path_str = i.split('|')[6]
		AS_path_str = AS_path_str.replace("{", "")
		AS_path_str = AS_path_str.replace("}", "")
		AS_path = AS_path_str.split(' ')
		
		lastASset = set()
		lastAS = []
		lastAS.append(AS_path[len(AS_path)-1])
		lastASset.add(lastAS[len(lastAS)-1])

		for x in range(len(AS_path)-2, -1, -1) :
			if(AS_path[x] not in lastASset) :
				lastAS.append(AS_path[x])
				lastASset.add(AS_path[x])
			if(len(lastAS) == 4) : break
		if(hijacking_type == "type_0") :
			type_0_cnt+=1
			if(lastAS[0] not in attacker_AS_dict.keys()) :
				attacker_AS_dict[lastAS[0]] = [0,0]

			attacker_AS_dict[lastAS[0]][0] += 1
		elif(hijacking_type == "type_1") :
			type_1_cnt+=1
			if(lastAS[1] not in attacker_AS_dict.keys()) :
				attacker_AS_dict[lastAS[1]] = [0,0]
			attacker_AS_dict[lastAS[1]][1] += 1
		
		checking_index += 1
		if(checking_index == len(btc_hijacking_list)) : break

	result_str = str(timestamp) + "|" + str(cnt)
	result_str += ":" + str(type_0_cnt) + "," + str(type_1_cnt) + "|"

	for i in attacker_AS_dict.keys() :
		total_HJ = attacker_AS_dict[i][0] + attacker_AS_dict[i][1] + attacker_AS_dict[i][2] + attacker_AS_dict[i][3]
		result_str += "AS" + str(i) + " - " + str(total_HJ) + ":" + str(attacker_AS_dict[i][0]) + "," + str(attacker_AS_dict[i][1]) + "|"
	result.write(result_str + '\n')
result.close()




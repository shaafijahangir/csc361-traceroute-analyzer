import TraceRouteAnalyzer

# R2 TTL probe calculation:
ttl_dict = {}
for p in TraceRouteAnalyzer.src:
	if p.ipv4.ttl not in ttl_dict:
		ttl_dict[p.ipv4.ttl] = []
	ttl_dict[p.ipv4.ttl].append(p)

for ttl in sorted(ttl_dict):
	print(f'ttl: {ttl:2d} -> {len(ttl_dict[ttl])} probes')
	print(len(ttl_dict[ttl]))
exit()
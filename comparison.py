import json
from collections import OrderedDict

RELEVANT_TAGS = {'45', '191'}
RELEVANT_EXT_TAGS = {'35', '108'}
RELEVANT_PREFIXES = ('wlan.ht', 'wlan.vht', 'wlan.txbf', 'wlan.asel', 'wlan.ext_tag.he', 'wlan.eht')


def load_json(file_path):
    def handle_dupes(pairs):
        d = OrderedDict()
        for k, v in pairs:
            if k in d:
                d[k] = d[k] if isinstance(d[k], list) else [d[k]]
                d[k].append(v)
            else:
                d[k] = v
        return d

    with open(file_path, 'r') as f:
        return json.load(f, object_pairs_hook=handle_dupes)


def extract_fields(data):
    fields = OrderedDict()

    def walk(obj):
        if isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, dict):
            if obj.get('wlan.tag.number') in RELEVANT_TAGS:
                flatten(obj)
            elif obj.get('wlan.ext_tag.number') in RELEVANT_EXT_TAGS:
                flatten(obj)
            elif str(obj.get('wlan.tag.ext_id', '')) in RELEVANT_EXT_TAGS:
                flatten(obj)
            else:
                for v in obj.values():
                    walk(v)

    def flatten(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.startswith(RELEVANT_PREFIXES) and not isinstance(v, (dict, list)):
                    fields[k] = str(v).lower()
                flatten(v)

    walk(data)
    return fields


ws = load_json('/Users/aikobudiman/Desktop/tmp/MRKP.json')
llm = load_json('parsed_beacons_LLM.json')

ws_fields = extract_fields(ws)
llm_fields = extract_fields(llm)

print(f"{'Field':<90} | {'Wireshark':<20} | {'LLM':<20} | Status")
print("-" * 120)

matches = 0
for key, ws_val in ws_fields.items():
    llm_val = llm_fields.get(key, "MISSING")

    ws_norm = ws_val.replace('0x', '').lstrip('0') or '0'
    llm_norm = llm_val.replace('0x', '').lstrip('0') or '0'

    ok = ws_norm == llm_norm
    if ok:
        matches += 1

    print(f"{key:<90} | {ws_val:<20} | {llm_val:<20} | {'MATCH' if ok else 'MISMATCH'}")

print("-" * 120)
print(f"{matches}/{len(ws_fields)} fields matched ({matches/len(ws_fields)*100:.1f}%)")
"""Typed business requests; milliseconds exist only at the wire boundary."""
import json
from pathlib import Path


def _validate(value, schema):
    kind=schema.get('type')
    if 'const' in schema and (type(value) is not type(schema['const']) or value!=schema['const']):
        raise ValueError('contract discriminator/version mismatch')
    if kind=='object':
        if not isinstance(value,dict): raise ValueError('object required')
        if set(schema.get('required',()))-set(value): raise ValueError('required contract field missing')
        props=schema['properties']
        if set(value)-set(props): raise ValueError('unknown or server-owned contract field')
        for key,item in value.items(): _validate(item,props[key])
    elif kind=='string':
        if not isinstance(value,str) or not schema.get('minLength',0)<=len(value)<=schema.get('maxLength',2048):
            raise ValueError('invalid string')
        if 'enum' in schema and value not in schema['enum']: raise ValueError('unknown business event type')
    elif kind in ('integer','number'):
        import math
        if type(value) not in ((int,) if kind=='integer' else (int,float)) or not math.isfinite(value):
            raise ValueError('finite number required')
        if value<schema.get('minimum',float('-inf')) or value>=schema.get('exclusiveMaximum',float('inf')):
            raise ValueError('number or time unit outside contract range')
    elif kind=='array':
        if not isinstance(value,list) or len(value)>schema.get('maxItems',256): raise ValueError('invalid array')
        for item in value: _validate(item,schema['items'])


def decision_event(request):
    schema=json.loads(Path(__file__).with_name('decision-request.schema.json').read_text())
    _validate(request,schema)
    event=dict(request['business_event'])
    if event['event_id']!=request['business_event_id']: raise ValueError('business event id mismatch')
    event['ts']=event.pop('occurred_at_ms')/1000
    event['report_ids']=request['sdk_report_ids']
    event['decision_request_id']=request['request_id']
    return event

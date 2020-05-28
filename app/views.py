import base64
import datetime
import json
import operator
import os
import re
import threading
import time

import requests
import yaml
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from kubernetes import config, client
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser
from rest_framework.viewsets import ModelViewSet

host = "https://10.0.0.210:6443/"
dr_url = "apis/networking.istio.io/v1alpha3/namespaces/default/destinationrules/"
vs_url = "apis/networking.istio.io/v1alpha3/namespaces/default/virtualservices/"


class AutoIstioApi(ModelViewSet):

    @csrf_exempt
    @action(detail=True, methods="POST")
    def create_circuit_breaking(self, request, *args, **kwargs):
        # DestinationRule
        circuit_breaking_json = yaml_to_json("circuit-breaking.yaml")
        request_data = JSONParser().parse(request)

        url = host + dr_url
        headers = {'Content-Type': 'application/json', 'Authorization': "bearer " + get_token()}

        requests.urllib3.disable_warnings()
        circuit_breaking_json['metadata']['name'] = request_data['name']

        circuit_breaking_json['spec']['host'] = request_data['host']

        circuit_breaking_json['spec']['trafficPolicy']['connectionPool']['tcp']['maxConnections'] \
            = request_data['maxConnections']

        circuit_breaking_json['spec']['trafficPolicy']['connectionPool']['http'][
            'maxRequestsPerConnection'] = request_data['maxRequestsPerConnection']

        circuit_breaking_json['spec']['trafficPolicy']['connectionPool']['http'][
            'http1MaxPendingRequests'] = request_data['maxConnections'] * request_data[
            'maxRequestsPerConnection']

        requests.post(url, headers=headers, data=json.dumps(circuit_breaking_json), verify=False)
        return JsonResponse({"status": "succeed"}, status=201)

    @csrf_exempt
    @action(detail=True, methods="POST")
    def create_canary_release(self, request, *args, **kwargs):
        request_data = JSONParser().parse(request)

        config.kube_config.load_kube_config()
        v1 = client.CoreV1Api()
        v1beta1 = client.ExtensionsV1beta1Api()

        service = v1.read_namespaced_service(name=request_data['host'], namespace='default')
        pod_ret = v1.list_namespaced_pod(namespace='default',
                                         label_selector="app=" + service.metadata.labels['app'])
        pod_list = pod_ret.items
        pod_info_dict = dict()
        for pod in pod_list:
            pod_info = PodInfo(pod.metadata.name, pod.metadata.labels['version'],
                               pod.metadata.creation_timestamp)
            pod_info_dict[pod_info.name] = pod_info

        pod_info_list = list()
        sorted_version = list()
        for pod in (sorted(pod_info_dict.values(), key=operator.attrgetter('version'))):
            sorted_version.append(pod.version)
            pod_info_list.append(pod)

        replicas = sorted_version.__len__() - 1
        sorted_version = list(sorted(set(sorted_version)))

        # DestinationRule
        mirroring_dr_json = yaml_to_json("mirroring-dr.yaml")

        url = host + dr_url
        headers = {'Content-Type': 'application/json', 'Authorization': "bearer " + get_token()}

        requests.urllib3.disable_warnings()
        mirroring_dr_json['metadata']['name'] = request_data['name']

        mirroring_dr_json['spec']['host'] = request_data['host']

        mirroring_dr_json['spec']['subsets'][0]['name'] = sorted_version[0]
        mirroring_dr_json['spec']['subsets'][0]['labels']['version'] = \
            sorted_version[0]

        mirroring_dr_json['spec']['subsets'][1]['name'] = sorted_version[1]
        mirroring_dr_json['spec']['subsets'][1]['labels']['version'] = \
            sorted_version[1]
        response = requests.post(url, headers=headers, data=json.dumps(mirroring_dr_json),
                                 verify=False)
        if response.status_code != 201:
            url = url + mirroring_dr_json['metadata']['name']
            headers = {'Content-Type': 'application/merge-patch+json',
                       'Authorization': "bearer " + get_token()}
            requests.patch(url, headers=headers, data=json.dumps(mirroring_dr_json),
                           verify=False)

        # VirtualService
        url = host + vs_url + request_data['name']
        headers = {'Content-Type': 'application/json', 'Authorization': "bearer " + get_token()}
        mirroring_vs_json = yaml_to_json("mirroring-vs.yaml")

        mirroring_vs_json['metadata']['name'] = request_data['name']

        mirroring_vs_json['spec']['hosts'][0] = request_data['host']

        mirroring_vs_json['spec']['http'][0]['route'][0]['destination']['host'] = \
            request_data['host']
        mirroring_vs_json['spec']['http'][0]['route'][0]['destination']['subset'] = \
            sorted_version[0]
        mirroring_vs_json['spec']['http'][0]['mirror']['host'] = request_data['host']
        mirroring_vs_json['spec']['http'][0]['mirror']['subset'] = sorted_version[1]

        mirroring_vs_json['spec']['http'][0]['mirror_percent'] = int(100 / replicas)
        response = requests.post(url, headers=headers, data=json.dumps(mirroring_vs_json),
                                 verify=False)

        if response.status_code != 201:
            headers = {'Content-Type': 'application/merge-patch+json',
                       'Authorization': "bearer " + get_token()}
            requests.patch(url, headers=headers, data=json.dumps(mirroring_vs_json), verify=False)

        plugin_thread = threading.Thread(target=canary_release_threading,
                                         args=(request_data,
                                               pod_info_list[pod_info_list.__len__() - 1].name,
                                               pod_info_list[
                                                   pod_info_list.__len__() - 1].creation_time,
                                               sorted_version))
        plugin_thread.start()

        return JsonResponse({"status": "succeed"}, status=202)

    @csrf_exempt
    @action(detail=True, methods="POST")
    def create_retry_policy(self, request, *args, **kwargs):
        # VirtualService
        url = host + vs_url
        headers = {'Content-Type': 'application/json', 'Authorization': "bearer " + get_token()}
        requests.urllib3.disable_warnings()

        request_data = JSONParser().parse(request)
        retries_json = yaml_to_json("retries.yaml")
        retries_json['metadata']['name'] = request_data['name']

        retries_json['spec']['hosts'][0] = request_data['host']

        retries_json['spec']['http'][0]['route'][0]['destination']['host'] = request_data['host']
        retries_json['spec']['http'][0]['retries']['attempts'] = request_data['attempts']
        retries_json['spec']['http'][0]['retries']['perTryTimeout'] = str(
            request_data['perTryTimeout']) + 's'

        requests.post(url, headers=headers, data=json.dumps(retries_json), verify=False)

        return JsonResponse({"status": "succeed"}, status=201)

    @csrf_exempt
    @action(detail=True, methods="DELETE")
    def destroy(self, request, *args, **kwargs):
        pass


class PodInfo:
    def __init__(self, name, version, creation_time):
        self.name = name
        self.version = version
        self.creation_time = creation_time


def get_token():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    secret = v1.read_namespaced_secret(namespace='default', name="default-token-dnr7h")
    return base64.b64decode(secret.data['token']).decode("utf-8")


def yaml_to_json(file):
    input_file = os.path.join(os.path.abspath(os.path.dirname(os.path.realpath(__file__))),
                              "templates", file)
    with open(input_file, 'r') as stream:
        try:
            json_object = json.dumps(yaml.safe_load(stream), sort_keys=True, indent=2)
            stream.close()
        except yaml.YAMLError as exc:
            json_object = "{}"
            print(exc)
    return eval(json_object)


def create_traffic_shifting_vs(request_data, sorted_version, new_version_weight):
    # VirtualService
    url = host + vs_url + request_data['name']
    headers = {'Content-Type': 'application/merge-patch+json',
               'Authorization': "bearer " + get_token()}
    traffic_shifting_vs_json = yaml_to_json("traffic-shifting-vs.yaml")

    traffic_shifting_vs_json['metadata']['name'] = request_data['name']

    traffic_shifting_vs_json['spec']['hosts'][0] = request_data['host']

    traffic_shifting_vs_json['spec']['http'][0]['route'][0]['destination']['host'] = \
        request_data['host']
    traffic_shifting_vs_json['spec']['http'][0]['route'][0]['destination']['subset'] = \
        sorted_version[0]
    traffic_shifting_vs_json['spec']['http'][0]['route'][0]['weight'] = 100 - new_version_weight
    traffic_shifting_vs_json['spec']['http'][0]['route'][1]['destination']['host'] = \
        request_data['host']
    traffic_shifting_vs_json['spec']['http'][0]['route'][1]['destination']['subset'] = \
        sorted_version[1]
    traffic_shifting_vs_json['spec']['http'][0]['route'][1]['weight'] = new_version_weight

    requests.patch(url, headers=headers, data=json.dumps(traffic_shifting_vs_json), verify=False)


def canary_release_threading(request_data, new_pod_name, new_pod_timestamp, sorted_version):
    v1 = client.CoreV1Api()
    v1beta1 = client.ExtensionsV1beta1Api()
    successes = 0
    while successes < 10:
        successes = 0
        failed = 0
        now_time = datetime.datetime.now()
        since_seconds = time.mktime(now_time.timetuple()) - time.mktime(
            new_pod_timestamp.timetuple())
        logs = v1.read_namespaced_pod_log(namespace='default',
                                          container='istio-proxy',
                                          name=new_pod_name,
                                          since_seconds=int(since_seconds))
        for line in logs.splitlines(keepends=False):
            http_2xx_pattern = re.compile("2[0-9][0-9]")
            http_3xx_pattern = re.compile("3[0-9][0-9]")
            http_4xx_pattern = re.compile("4[0-9][0-9]")
            http_5xx_pattern = re.compile("5[0-9][0-9]")
            start_mark = re.compile(
                '^\\[([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):'
                '([0-5][0-9]):([0-5][0-9]|60)(\\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):'
                '[0-5][0-9]))\\]$')
            line_list = line.split(" ")
            if start_mark.match(line_list[0]):
                if http_2xx_pattern.match(line_list[4]):
                    successes = successes + 1
                elif (http_3xx_pattern.match(line_list[4]) or
                      http_4xx_pattern.match(line_list[4]) or
                      http_5xx_pattern.match(line_list[4])):
                    failed = failed + 1
        if failed >= 5:
            return
    print(sorted_version)
    service = v1.read_namespaced_service(name=request_data['host'], namespace='default')
    deployment_label = "app=" + service.metadata.labels['app'] + ",version=" + sorted_version[0]
    old_deployment_ret = v1beta1.list_namespaced_deployment(namespace='default',
                                                            label_selector=deployment_label)
    old_deployment = old_deployment_ret.items[0]

    deployment_label = "app=" + service.metadata.labels['app'] + ",version=" + sorted_version[1]
    new_deployment_ret = v1beta1.list_namespaced_deployment(namespace='default',
                                                            label_selector=deployment_label)
    new_deployment = new_deployment_ret.items[0]

    new_deployment.spec.replicas = old_deployment.spec.replicas
    v1beta1.patch_namespaced_deployment(new_deployment.metadata.name, "default", new_deployment)

    time.sleep(10)
    for i in range(101):
        print(i)
        create_traffic_shifting_vs(request_data, sorted_version, i)
        time.sleep(1)

    old_deployment.spec.replicas = 0
    v1beta1.patch_namespaced_deployment(old_deployment.metadata.name, "default", old_deployment)
    print('finish canary deploy')

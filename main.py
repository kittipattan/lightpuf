from leader_rasppi import LeaderPi
from iot_rasppi import IoTPi
from server import LocalServer
from fog import Fog
from pypuf.io import random_inputs
from typing import List
from threading import Thread
import random
import string
from utils.measurement import measure_computation_cost, measure_throughput


def initialize_group(
    fog_nodes: int, devices_per_node: int, server: LocalServer, IoTs: List[List[IoTPi]]
):
    for g in range(fog_nodes):
        # Add Leader
        group: List[IoTPi] = []

        # Add IoT members
        for i in range(1, devices_per_node + 1):
            id = (g * devices_per_node) + i
            gid = g + 1
            data = f"sample data from IoT device {id} {''.join(random.choices(string.ascii_letters,k=73))}"
            # data = f"sample data from IoT device {id}"

            iot = IoTPi(id, gid, id, data)
            if i == 1:
                iot = LeaderPi(id, gid, id, data)

            challenge = random_inputs(64, 256, id)
            challenge = (1 - challenge) // 2
            response = iot.genResponse(challenge)
            server.registerCRP(id, gid, challenge, response)

            group.append(iot)

        IoTs.append(group)


def authen_leader_fog(leader: LeaderPi, fog: Fog):
    leader_proof = leader.genProof()
    # measure_computation_cost(leader.genProof, "Leader NIZKP Proof", 1000, leader.data)
    fog_proof = fog.genProof()
    # measure_computation_cost(fog.verifyProof, "Fog NIZKP Verify", 1000, leader_proof)
    fog.verifyProof(leader_proof)
    leader.verifyProof(fog_proof)

def authen_iot_fog(group: List[IoTPi], fog: Fog):
    threads: List[Thread] = []

    for iot in group:
        # t = Thread(target=lambda: fog.recvData(iot.createPacket()))
        # threads.append(t)
        # t.start()
        fog.recvData(iot.createPacket())

    # for t in threads:
    #     t.join()

    fog.verifyToken(group)

def main(fog_nodes, devices_per_node):
    fog_nodes = fog_nodes
    devices_per_node = devices_per_node

    IoTs: List[List[IoTPi]] = []
    server = LocalServer()
    fogs: List[Fog] = [Fog() for _ in range(fog_nodes)]

    # Reset the table
    server.dropCRP()

    # PHASE 1: System Initialization
        # Create IoT groups and register CRP into the LocalServer
    print(
        " \n###################################### Initialization ######################################\n "
    )
    print(f"    no. of groups: {fog_nodes}")
    print(f"    no. of devices per group: {devices_per_node}")

    initialize_group(fog_nodes, devices_per_node, server, IoTs)
    
    # Generate pair key between Leader and Device
    for group, fog in zip(IoTs, fogs):
        device_crps = []
        for iot in group:
            # CRP retrieval
            device_crps.append(server.sendCRP(iot.id))
            
        # PHASE 2: Key Exchange
        fog.deriveDeviceKey(device_crps, group)
        
    # PHASE 3: Group Key Generation
    for group in IoTs:
        leader: LeaderPi = group[0]
        leader.sendGroupKey(group)

    # PHASE 4: Group Authentication and Secure Channel Establishment with Fog Node
    for group, fog in zip(IoTs, fogs):
        leader: LeaderPi = group[0]
        authen_leader_fog(leader, fog)

    # PHASE 5: Data Authentication and Integrity Verification
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        
        # Secret Generation +
        # AES Key Encryption and Key Splitting
        messages_to_leader = fog.genSec(group)
        
        # Secret distribution
        leader.distributeSecret(messages_to_leader, group)

    # Data Authentication
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        # [print(iot.id, end=" ") for iot in group]
        # authen_iot_fog(group, fog)
        
        def test_data_authentication():
            authen_leader_fog(leader, fog)
            messages_to_leader = fog.genSec(group)
            leader.distributeSecret(messages_to_leader, group)    
            authen_iot_fog(group, fog)

        # Data Authentication
        measure_computation_cost(test_data_authentication, "Data Authentication", 1000)
        
        def test_throughput():
            authen_leader_fog(leader, fog)
            messages_to_leader = fog.genSec(group)
            leader.distributeSecret(messages_to_leader, group)
            authen_iot_fog(group, fog)

        # Throughput
        measure_throughput(test_throughput, "Throughput", [50])
        
        # measure_computation_cost(authen_iot_fog, "Authen IoT-Fog", 100, group, fog)

        # print(f"All {devices_per_node} IoTs data authen success")

    # Cloud Uploading
    # for group, fog in zip(IoTs, fogs):
        # gid = group[0].gid
        # fog_id = gid
        # upload_threads = []

        # t = Thread(
        #     target=fog.uploadToCloud, args=(len(fogs), devices_per_node, fog_id, gid)
        # )
        # upload_threads.append(t)
        # t.start()

        # for t in upload_threads:
        #     t.join()

    return 0


if __name__ == "__main__":
    for n in [50]:
        main(1,n)

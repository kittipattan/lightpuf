import time
import statistics
import math
from threading import Thread

def measure_computation_cost(func, name, round, *args, **kwargs):

    print(f"""\n{'-'*70}
START MEASURING '{name}' {round} rounds
{'-'*70}\n""")

    # execution time, cpu usage, memory usage

    ### get started ###
    num_round = round
    measurements = []
    # execution_time = 0

    for _ in range(num_round):
        start_time = time.time()

        ### call function
        func(*args, **kwargs)

        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        measurements.append(duration_ms)  # in ms

        # execution_time += (end_time - start_time)
        # new_execution_time = end_time - start_time
        # if (new_execution_time > execution_time):
        #   execution_time = new_execution_time

    # exec_time = (execution_time/num_round)*1000
    # exec_time = execution_time*1000

    avg = statistics.mean(measurements)
    sd = statistics.stdev(measurements)

    print("===== Experiment Result =====\n")
    # print(f"Average Execution Time: {exec_time:.5f} ms")
    print(f"Average Execution Time: {avg:.5f} ms")
    print(f"Standard Deviation: {sd:.5f} ms")
    print("\n============ END ============\n")

    return (avg, sd)

# Not working as expected when the no_group is >1
# - Need to input the leader for each group separately
def measure_throughput(func, name, request_no_list, rounds=100, batch_size=50, *args, **kwargs):
    print(f"""\n{'-'*70}
START MEASURING '{name}'
{'-'*70}\n""")

    for no_request in request_no_list:
        threads = []
        measurements = []
        for _ in range(rounds):
            no_group = math.ceil(no_request/batch_size)
            start_time = time.time()
            for _ in range(no_group):
                t = Thread(target=lambda: func(*args, **kwargs))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
            end_time = time.time()
            total_time = end_time - start_time
            try:
                throughput = no_request / total_time
            except:
                throughput = no_request
            measurements.append(throughput)
        
        avg = statistics.mean(measurements)
        sd = statistics.stdev(measurements)

        print(f"Concurrent devices: {no_request}, Throughput: {avg:.2f} transactions/sec with SD: {sd:.2f}")
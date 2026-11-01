"""
routing/dijkstra.py — Shortest-path computation using Dijkstra's algorithm.

Dijkstra's algorithm finds the shortest paths from a single *source* node
to every other node in a weighted, non-negative-edge graph.

How it works (high-level):
  1. Start with dist[source] = 0 and dist[everything else] = ∞.
  2. Use a priority queue (min-heap) to always process the closest
     unvisited node next.
  3. For each unvisited node *u*, relax all edges (u → v):
       if dist[u] + cost(u,v) < dist[v]:
           dist[v] = dist[u] + cost(u,v)
           prev[v] = u
  4. Once all reachable nodes are visited, dist[] holds shortest distances
     and prev[] lets you reconstruct the actual path.

Time complexity: O((V + E) log V) with a binary heap.
"""

import heapq


def dijkstra(
    graph: dict[int, dict[int, int]],
    source: int,
) -> tuple[dict[int, int], dict[int, int | None]]:
    """
    Run Dijkstra's algorithm from *source* on *graph*.

    Parameters
    ----------
    graph  : Adjacency list  {node: {neighbor: cost, ...}, ...}.
    source : The starting node ID.

    Returns
    -------
    dist : {node: shortest_distance_from_source}
    prev : {node: previous_node_on_shortest_path}  (prev[source] is None)
    """
    # Collect all nodes that appear anywhere in the graph
    all_nodes: set[int] = set()
    for n, nbrs in graph.items():
        all_nodes.add(n)
        all_nodes.update(nbrs.keys())

    INF = float("inf")
    dist: dict[int, int | float] = {n: INF for n in all_nodes}
    prev: dict[int, int | None]  = {n: None for n in all_nodes}
    dist[source] = 0

    # Min-heap entries: (distance, node_id)
    heap: list[tuple[int | float, int]] = [(0, source)]
    visited: set[int] = set()

    while heap:
        d_u, u = heapq.heappop(heap)

        if u in visited:
            continue                       # Already found a shorter path
        visited.add(u)

        for v, cost in graph.get(u, {}).items():
            alt = d_u + cost
            if alt < dist[v]:
                dist[v] = alt
                prev[v] = u
                heapq.heappush(heap, (alt, v))

    # Convert dist values to int where finite
    dist_int: dict[int, int] = {}
    for n, d in dist.items():
        dist_int[n] = d if d != INF else 999999

    return dist_int, prev


def compute_forwarding_table(
    graph: dict[int, dict[int, int]],
    source: int,
) -> dict[int, int | None]:
    """
    Build a Forwarding Information Base (FIB) for *source*.

    The FIB maps every reachable destination to the *next hop* — the
    immediate neighbour that lies on the shortest path to that destination.

    Example:
      If the shortest path from A to D is A → B → C → D, then
      forwarding_table[D] = B   (next hop is B).

    Returns
    -------
    {dest_node: next_hop_node}   (None if dest is unreachable).
    """
    dist, prev = dijkstra(graph, source)

    fib: dict[int, int | None] = {}
    for dest in dist:
        if dest == source:
            continue

        if prev[dest] is None:
            fib[dest] = None               # Unreachable
            continue

        # Walk backwards from dest to source to find the first hop
        current = dest
        while prev[current] is not None and prev[current] != source:
            current = prev[current]

        # `current` is now the direct neighbour of source on the path
        if prev[current] == source:
            fib[dest] = current
        else:
            fib[dest] = None               # Shouldn't happen in a connected graph

    return fib

# AWS
## Provisioning an instance
```bash
docker-machine create --driver amazonec2 --amazonec2-instance-type "m5.2xlarge" --amazonec2-root-size "100" capture
```
## Entering environment
```bash
eval "$(docker-machine env capture)"
```
## Making folders
```bash
docker-machine ssh capture sudo mkdir -p /mnt/data/pcap_data/test
docker-machine ssh capture sudo chmod -R 777 /mnt/data/pcap_data/test
```
## Running job
### Debug case: 1 worker
```bash
make run
```
### Parallel case: N workers
```bash
make scale
```
## Monitoring job
```bash
make logs
```

#  TODO create an image parser to check images for correctness
import yaml
import inspect


def parse_image(image_name):
    path = '/'.join(inspect.getfile(parse_image).split('/')[:-1]) + '/'
    with open(path+'images.yaml') as fIn:
        images = yaml.load(fIn, Loader=yaml.FullLoader)
    assert image_name in images
    with open(path + images[image_name]['path'] + '.yaml') as fIn:
        image = yaml.load(fIn, Loader=yaml.FullLoader)
    image = image['Test_Host']
    assert 'System info' in image
    assert 'User Info' in image
    assert 'Processes' in image
    for proc in image['Processes']:
        assert 'Username' in proc, f'not username in {proc} in image {image_name}'
        assert 'PID' in proc, f'not pid in {proc} in image {image_name}'
        assert 'PPID' in proc, f'not ppid in {proc} in image {image_name}'
        assert 'Process Name' in proc, f'not name in {proc} in image {image_name}'

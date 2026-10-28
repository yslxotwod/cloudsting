project('cloudsting', 'c',
    version: '1.0.0',
    meson_version: '>= 1.0',
    default_options: ['c_std=c17', 'warning_level=1'])

gtk4 = dependency('gtk4', version: '>= 4.10')
vte = dependency('vte-2.91-gtk4', version: '>= 0.70')

conf_data = configuration_data()
conf_data.set_quoted('CLOUDSTING_ROOT', meson.project_source_root())
conf_data.set10('HAVE_CONFIG_H', 1)

configure_file(
    output: 'config.h',
    configuration: conf_data)

cloudsting_sources = files('src/main1.c')

executable('cloudsting',
    cloudsting_sources,
    dependencies: [gtk4, vte],
    install: true,
    gui_app: true)

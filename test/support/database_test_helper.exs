#
# This file is part of Astarte.
#
# Copyright 2017 - 2025 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Astarte.DataAccess.DatabaseTestHelper do
  @create_autotestrealm """
    CREATE KEYSPACE autotestrealm
      WITH
        replication = {'class': 'SimpleStrategy', 'replication_factor': '1'} AND
        durable_writes = true;
  """

  @create_kv_store """
    CREATE TABLE autotestrealm.kv_store (
      group varchar,
      key varchar,
      value blob,

      PRIMARY KEY ((group), key)
    );
  """

  @create_names_table """
    CREATE TABLE autotestrealm.names (
      object_name varchar,
      object_type int,
      object_uuid uuid,

      PRIMARY KEY ((object_name), object_type)
    );
  """

  @create_devices_table """
      CREATE TABLE autotestrealm.devices (
        device_id uuid,
        aliases map<ascii, varchar>,
        introspection map<ascii, int>,
        introspection_minor map<ascii, int>,
        old_introspection map<frozen<tuple<ascii, int>>, int>,
        protocol_revision int,
        first_registration timestamp,
        credentials_secret ascii,
        inhibit_credentials_request boolean,
        cert_serial ascii,
        cert_aki ascii,
        first_credentials_request timestamp,
        last_connection timestamp,
        last_disconnection timestamp,
        connected boolean,
        pending_empty_cache boolean,
        total_received_msgs bigint,
        total_received_bytes bigint,
        exchanged_bytes_by_interface map<frozen<tuple<ascii, int>>, bigint>,
        exchanged_msgs_by_interface map<frozen<tuple<ascii, int>>, bigint>,
        last_credentials_request_ip inet,
        last_seen_ip inet,
        attributes map<varchar, varchar>,

        groups map<text, timeuuid>,

        PRIMARY KEY (device_id)
      );
  """

  @insert_device_statement """
  INSERT INTO autotestrealm.devices
  (
     device_id, aliases, connected, last_connection, last_disconnection,
     first_registration, first_credentials_request, last_seen_ip, last_credentials_request_ip,
     total_received_msgs, total_received_bytes,
     introspection, introspection_minor
  )
  VALUES
    (
      :device_id, :aliases, false, '2017-09-28 04:05+0020', '2017-09-30 04:05+0940',
      '2016-08-15 11:05+0121', '2016-08-20 11:05+0121', '198.51.100.81', '198.51.100.89',
      45000, :total_received_bytes,
      {'com.test.LCDMonitor' : 1, 'com.test.SimpleStreamTest' : 1,
       'com.example.TestObject': 1, 'com.example.PixelsConfiguration': 1},
      {'com.test.LCDMonitor' : 3, 'com.test.SimpleStreamTest' : 0,
       'com.example.TestObject': 5, 'com.example.PixelsConfiguration': 0}
    );
  """

  @insert_alias_statement """
    INSERT INTO autotestrealm.names (object_name, object_type, object_uuid) VALUES (:alias, 1, :device_id);
  """

  @create_interfaces_table """
      CREATE TABLE autotestrealm.interfaces (
        name ascii,
        major_version int,
        minor_version int,
        interface_id uuid,
        storage_type int,
        storage ascii,
        type int,
        ownership int,
        aggregation int,
        automaton_transitions blob,
        automaton_accepting_states blob,
        description varchar,
        doc varchar,

        PRIMARY KEY (name, major_version)
      );
  """

  @create_endpoints_table """
      CREATE TABLE autotestrealm.endpoints (
        interface_id uuid,
        endpoint_id uuid,
        interface_name ascii,
        interface_major_version int,
        interface_minor_version int,
        interface_type int,
        endpoint ascii,
        value_type int,
        reliability int,
        retention int,
        database_retention_policy int,
        database_retention_ttl int,
        expiry int,
        allow_unset boolean,
        explicit_timestamp boolean,
        description varchar,
        doc varchar,

        PRIMARY KEY ((interface_id), endpoint_id)
      );
  """

  @insert_endpoints [
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (798b93a5-842e-bbad-2e4d-d20306838051, e6f73631-effc-1d7e-ad52-d3f3a3bae50b, False, '/time/from', 0, 0, 3, 'com.test.LCDMonitor', 1, 1, 1, 5);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (798b93a5-842e-bbad-2e4d-d20306838051, 2b2c63dd-bbd9-5735-6d4a-8e56f504edda, False, '/time/to', 0, 0, 3, 'com.test.LCDMonitor', 1, 1, 1, 5);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (798b93a5-842e-bbad-2e4d-d20306838051, 801e1035-5fdf-7069-8e6e-3fd2792699ab, False, '/weekSchedule/%{day}/start', 0, 0, 3, 'com.test.LCDMonitor', 1, 1, 1, 5);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (798b93a5-842e-bbad-2e4d-d20306838051, 4fe5034a-3d9b-99ec-7ec3-b23716303d33, False, '/lcdCommand', 0, 0, 3, 'com.test.LCDMonitor', 1, 1, 1, 7);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (798b93a5-842e-bbad-2e4d-d20306838051, 8ebb62b3-60c1-4ba2-4172-9ddedd809c9f, False, '/weekSchedule/%{day}/stop', 0, 0, 3, 'com.test.LCDMonitor', 1, 1, 1, 5);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry,
          interface_major_version, interface_minor_version, interface_name, interface_type,
          reliability, retention, database_retention_policy, database_retention_ttl, value_type
        ) VALUES (0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924,
          False, '/%{itemIndex}/value', 0, 1, 0, 'com.test.SimpleStreamTest', 2, 3, 1, 2, 120, 3
        );
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 3907d41d-5bca-329d-9e51-4cea2a54a99a, False, '/foo/%{param}/stringValue', 0, 1, 0, 'com.test.SimpleStreamTest', 2, 3, 1, 7);
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 7aa44c11-2273-47d9-e624-4ae029dedeaa, False, '/foo/%{param}/blobValue', 0, 1, 0, 'com.test.SimpleStreamTest', 2, 3, 1, 11);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry,
          interface_major_version, interface_minor_version, interface_name, interface_type,
          reliability, retention, database_retention_policy, value_type
        ) VALUES (0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, eff957cf-03df-deed-9784-a8708e3d8cb9,
          False, '/foo/%{param}/longValue', 0, 1, 0, 'com.test.SimpleStreamTest', 2, 3, 1, 1, 5
        );
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 346c80e4-ca99-6274-81f6-7b1c1be59521, False, '/foo/%{param}/timestampValue', 0, 1, 0, 'com.test.SimpleStreamTest', 2, 3, 1, 13);
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (db576345-80b1-5358-f305-d77ec39b3d84, 7c9f14e8-4f2f-977f-c126-d5e1bb9876e7, False, '/string', 0, 1, 5, 'com.example.TestObject', 2, 2, 3, 7);
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (db576345-80b1-5358-f305-d77ec39b3d84, 3b39fd3a-e261-26ff-e523-4c2dd150b864, False, '/value', 0, 1, 5, 'com.example.TestObject', 2, 2, 3, 1);
    """,
    """
    INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version, interface_minor_version, interface_name, interface_type, reliability, retention, value_type) VALUES
        (9651f167-a619-3ff5-1c4e-6771fb1929d4, 342c0830-f496-0db0-6776-2d1a7e534022, True, '/%{x}/%{y}/color', 0, 1, 0, 'com.example.PixelsConfiguration', 1, 1, 1, 7);
    """,
    """
      INSERT INTO autotestrealm.endpoints (interface_id, endpoint_id, allow_unset, endpoint, expiry, interface_major_version,
        interface_minor_version, interface_name, interface_type, reliability, retention, value_type, doc, description,
        explicit_timestamp) VALUES
        (53d09b30-67cd-dcf3-de1e-2870ead21f13, 66636ae8-e8a7-1459-5a21-ee40b65fcdf4, False, '/new/interface/value', 0, 0,
        1, 'org.astarte-platform.NewInterface', 1, 1, 1, 1, 'The doc.', 'The description.', false);
    """
  ]

  @create_individual_properties_table """
    CREATE TABLE autotestrealm.individual_properties (
      device_id uuid,
      interface_id uuid,
      endpoint_id uuid,
      path varchar,
      reception_timestamp timestamp,
      reception_timestamp_submillis smallint,

      double_value double,
      integer_value int,
      boolean_value boolean,
      longinteger_value bigint,
      string_value varchar,
      binaryblob_value blob,
      datetime_value timestamp,
      doublearray_value list<double>,
      integerarray_value list<int>,
      booleanarray_value list<boolean>,
      longintegerarray_value list<bigint>,
      stringarray_value list<varchar>,
      binaryblobarray_value list<blob>,
      datetimearray_value list<timestamp>,

      PRIMARY KEY((device_id, interface_id), endpoint_id, path)
    );
  """

  @create_individual_datastreams_table """
    CREATE TABLE IF NOT EXISTS autotestrealm.individual_datastreams (
      device_id uuid,
      interface_id uuid,
      endpoint_id uuid,
      path varchar,
      value_timestamp timestamp,
      reception_timestamp timestamp,
      reception_timestamp_submillis smallint,

      double_value double,
      integer_value int,
      boolean_value boolean,
      longinteger_value bigint,
      string_value varchar,
      binaryblob_value blob,
      datetime_value timestamp,
      doublearray_value list<double>,
      integerarray_value list<int>,
      booleanarray_value list<boolean>,
      longintegerarray_value list<bigint>,
      stringarray_value list<varchar>,
      binaryblobarray_value list<blob>,
      datetimearray_value list<timestamp>,

      PRIMARY KEY((device_id, interface_id, endpoint_id, path), value_timestamp, reception_timestamp, reception_timestamp_submillis)
    );
  """

  @create_test_object_table """
    CREATE TABLE autotestrealm.com_example_testobject_v1 (
      device_id uuid,
      path varchar,
      reception_timestamp timestamp,
      v_string varchar,
      v_value double,
      PRIMARY KEY ((device_id, path), reception_timestamp)
    );
  """

  @insert_values [
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, e6f73631-effc-1d7e-ad52-d3f3a3bae50b, '/time/from', 8);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 2b2c63dd-bbd9-5735-6d4a-8e56f504edda, '/time/to', 20);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 801e1035-5fdf-7069-8e6e-3fd2792699ab, '/weekSchedule/2/start', 12);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 801e1035-5fdf-7069-8e6e-3fd2792699ab, '/weekSchedule/3/start', 15);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 801e1035-5fdf-7069-8e6e-3fd2792699ab, '/weekSchedule/4/start', 16);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 8ebb62b3-60c1-4ba2-4172-9ddedd809c9f, '/weekSchedule/2/stop', 15);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 8ebb62b3-60c1-4ba2-4172-9ddedd809c9f, '/weekSchedule/3/stop', 16);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, longinteger_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 8ebb62b3-60c1-4ba2-4172-9ddedd809c9f, '/weekSchedule/4/stop', 18);
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, string_value) VALUES
       (7f454c46-0201-0100-0000-000000000000, 798b93a5-842e-bbad-2e4d-d20306838051, 4fe5034a-3d9b-99ec-7ec3-b23716303d33, '/lcdCommand', 'SWITCH_ON');
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, reception_timestamp, reception_timestamp_submillis, datetime_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-30 07:10+0000', 0, '2017-09-30 07:11+0000');
    """,
    """
      INSERT INTO autotestrealm.individual_datastreams (device_id, interface_id, endpoint_id, path, value_timestamp, reception_timestamp, reception_timestamp_submillis, integer_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-28 04:05+0000', '2017-09-28 05:05+0000', 0, 0);
    """,
    """
      INSERT INTO autotestrealm.individual_datastreams (device_id, interface_id, endpoint_id, path, value_timestamp, reception_timestamp, reception_timestamp_submillis, integer_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-28 04:06+0000', '2017-09-28 05:06+0000', 0, 1);
    """,
    """
      INSERT INTO autotestrealm.individual_datastreams (device_id, interface_id, endpoint_id, path, value_timestamp, reception_timestamp, reception_timestamp_submillis, integer_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-28 04:07+0000', '2017-09-28 05:07+0000', 0, 2);
    """,
    """
      INSERT INTO autotestrealm.individual_datastreams (device_id, interface_id, endpoint_id, path, value_timestamp, reception_timestamp, reception_timestamp_submillis, integer_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-29 05:07+0000', '2017-09-29 06:07+0000', 0, 3);
    """,
    """
      INSERT INTO autotestrealm.individual_datastreams (device_id, interface_id, endpoint_id, path, value_timestamp, reception_timestamp, reception_timestamp_submillis, integer_value) VALUES
        (7f454c46-0201-0100-0000-000000000000, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 75010e1b-199e-eefc-dd35-d254b0e20924, '/0/value', '2017-09-30 07:10+0000', '2017-09-30 08:10+0000', 0, 4);
    """,
    """
      INSERT INTO autotestrealm.com_example_testobject_v1 (device_id, path, reception_timestamp, v_value, v_string) VALUES
        (7f454c46-0201-0100-0000-000000000000, '/', '2017-09-30 07:10+0000', 1.1, 'aaa');
    """,
    """
      INSERT INTO autotestrealm.com_example_testobject_v1 (device_id, path, reception_timestamp, v_value, v_string) VALUES
        (7f454c46-0201-0100-0000-000000000000, '/', '2017-09-30 07:12+0000', 2.2, 'bbb');
    """,
    """
      INSERT INTO autotestrealm.com_example_testobject_v1 (device_id, path, reception_timestamp, v_value, v_string) VALUES
        (7f454c46-0201-0100-0000-000000000000, '/', '2017-09-30 07:13+0000', 3.3, 'ccc');
    """,
    """
      INSERT INTO autotestrealm.individual_properties (device_id, interface_id, endpoint_id, path, reception_timestamp) VALUES
        (7f454c46-0201-0100-0000-000000000000, db576345-80b1-5358-f305-d77ec39b3d84, 7d03ec11-a59f-47fa-c8f0-0bc9b022649f, '/', '2017-09-30 07:12+0000');
    """
  ]

  @insert_into_interface_0 """
  INSERT INTO autotestrealm.interfaces (name, major_version, automaton_accepting_states, automaton_transitions, aggregation, interface_id, minor_version, ownership, storage, storage_type, type) VALUES
    ('com.test.LCDMonitor', 1, :automaton_accepting_states, :automaton_transitions, 1, 798b93a5-842e-bbad-2e4d-d20306838051, 3, 1, 'individual_properties', 1, 1)
  """

  @insert_into_interface_1 """
  INSERT INTO autotestrealm.interfaces (name, major_version, automaton_accepting_states, automaton_transitions, aggregation, interface_id, minor_version, ownership, storage, storage_type, type) VALUES
    ('com.test.SimpleStreamTest', 1, :automaton_accepting_states, :automaton_transitions, 1, 0a0da77d-85b5-93d9-d4d2-bd26dd18c9af, 0, 1, 'individual_datastreams', 2, 2)
  """

  @insert_into_interface_2 """
  INSERT INTO autotestrealm.interfaces (name, major_version, aggregation, interface_id, minor_version, ownership, storage, storage_type, type) VALUES
    ('com.example.TestObject', 1, 2, db576345-80b1-5358-f305-d77ec39b3d84, 5, 1, 'com_example_testobject_v1', 5, 2)
  """

  @insert_into_interface_3 """
  INSERT INTO autotestrealm.interfaces (name, major_version, automaton_accepting_states, automaton_transitions, aggregation, interface_id, minor_version, ownership, storage, storage_type, type) VALUES
    ('com.example.PixelsConfiguration', 1, :automaton_accepting_states, :automaton_transitions, 1, 9651f167-a619-3ff5-1c4e-6771fb1929d4, 0, 2, 'individual_properties', 1, 1)
  """

  @insert_into_interface_4 """
  INSERT INTO autotestrealm.interfaces (name, major_version, automaton_accepting_states, automaton_transitions, aggregation,
    interface_id, minor_version, ownership, storage, storage_type, type) VALUES
    ('org.astarte-platform.NewInterface', 0, :automaton_accepting_states, :automaton_transitions, 1,
    53d09b30-67cd-dcf3-de1e-2870ead21f13, 1, 1, 'individual_properties', 1, 1)
  """

  def create_test_keyspace(conn) do
    case Xandra.execute(conn, @create_autotestrealm) do
      {:ok, _} ->
        Xandra.execute!(conn, @create_devices_table)
        Xandra.execute!(conn, @create_names_table)
        Xandra.execute!(conn, @create_kv_store)
        Xandra.execute!(conn, @create_endpoints_table)
        Xandra.execute!(conn, @create_individual_properties_table)
        Xandra.execute!(conn, @create_individual_datastreams_table)
        Xandra.execute!(conn, @create_test_object_table)
        Xandra.execute!(conn, @create_interfaces_table)
        :ok

      {:error, msg} ->
        {:error, msg}
    end
  end

  def seed_data(conn) do
    Enum.each(
      ["interfaces", "endpoints", "individual_properties", "individual_datastreams", "kv_store"],
      fn table ->
        Xandra.execute!(conn, "TRUNCATE autotestrealm.#{table}")
      end
    )

    devices_list = [
      {"f0VMRgIBAQAAAAAAAAAAAA", 4_500_000, %{"display_name" => "device_a"}},
      {"olFkumNuZ_J0f_d6-8XCDg", 10, nil},
      {"4UQbIokuRufdtbVZt9AsLg", 22, %{"display_name" => "device_b", "serial" => "1234"}},
      {"aWag-VlVKC--1S-vfzZ9uQ", 0, %{"display_name" => "device_c"}},
      {"DKxaeZ9LzUZLz7WPTTAEAA", 300, %{"display_name" => "device_d"}}
    ]

    for {encoded_device_id, total_received_bytes, aliases} <- devices_list do
      device_id = Base.url_decode64!(encoded_device_id, padding: false)

      insert_device_query_params = %{
        "device_id" => device_id,
        "aliases" => aliases,
        "total_received_bytes" => total_received_bytes
      }

      insert_device_query_prp = Xandra.prepare!(conn, @insert_device_statement)

      Xandra.execute!(conn, insert_device_query_prp, insert_device_query_params)

      for {_key, device_alias} <- aliases || %{} do
        insert_alias_query_params = %{
          "device_id" => device_id,
          "alias" => device_alias
        }

        alias_query_prepared = Xandra.prepare!(conn, @insert_alias_statement)

        Xandra.execute!(conn, alias_query_prepared, insert_alias_query_params)
      end
    end

    insert_into_interface_0_params = %{
      "automaton_accepting_states" =>
        Base.decode64!(
          "g3QAAAAFYQNtAAAAEIAeEDVf33Bpjm4/0nkmmathBG0AAAAQjrtis2DBS6JBcp3e3YCcn2EFbQAAABBP5QNKPZuZ7H7DsjcWMD0zYQdtAAAAEOb3NjHv/B1+rVLT86O65QthCG0AAAAQKyxj3bvZVzVtSo5W9QTt2g=="
        ),
      "automaton_transitions" =>
        Base.decode64!(
          "g3QAAAAIaAJhAG0AAAAKbGNkQ29tbWFuZGEFaAJhAG0AAAAEdGltZWEGaAJhAG0AAAAMd2Vla1NjaGVkdWxlYQFoAmEBbQAAAABhAmgCYQJtAAAABXN0YXJ0YQNoAmECbQAAAARzdG9wYQRoAmEGbQAAAARmcm9tYQdoAmEGbQAAAAJ0b2EI"
        )
    }

    insert_into_interface_0_prepared = Xandra.prepare!(conn, @insert_into_interface_0)

    Xandra.execute!(conn, insert_into_interface_0_prepared, insert_into_interface_0_params)

    insert_into_interface_1_params = %{
      "automaton_accepting_states" =>
        Base.decode64!(
          "g3QAAAAFYQJtAAAAEHUBDhsZnu783TXSVLDiCSRhBW0AAAAQOQfUHVvKMp2eUUzqKlSpmmEGbQAAABB6pEwRInNH2eYkSuAp3t6qYQdtAAAAEO/5V88D397tl4SocI49jLlhCG0AAAAQNGyA5MqZYnSB9nscG+WVIQ=="
        ),
      "automaton_transitions" =>
        Base.decode64!(
          "g3QAAAAIaAJhAG0AAAAAYQFoAmEAbQAAAANmb29hA2gCYQFtAAAABXZhbHVlYQJoAmEDbQAAAABhBGgCYQRtAAAACWJsb2JWYWx1ZWEGaAJhBG0AAAAJbG9uZ1ZhbHVlYQdoAmEEbQAAAAtzdHJpbmdWYWx1ZWEFaAJhBG0AAAAOdGltZXN0YW1wVmFsdWVhCA=="
        )
    }

    insert_into_interface_1_prepared = Xandra.prepare!(conn, @insert_into_interface_1)

    Xandra.execute!(conn, insert_into_interface_1_prepared, insert_into_interface_1_params)

    Xandra.execute!(conn, @insert_into_interface_2, %{})

    insert_into_interface_3_params = %{
      "automaton_accepting_states" => Base.decode64!("g3QAAAABYQNtAAAAEOPZVKNVUNqw17mW3O0hiYc="),
      "automaton_transitions" =>
        Base.decode64!("g3QAAAADaAJhAG0AAAAAYQFoAmEBbQAAAABhAmgCYQJtAAAABWNvbG9yYQM=")
    }

    insert_into_interface_3_prepared = Xandra.prepare!(conn, @insert_into_interface_3)

    Xandra.execute!(conn, insert_into_interface_3_prepared, insert_into_interface_3_params)

    insert_into_interface_4_params = %{
      "automaton_accepting_states" => Base.decode64!("g3QAAAABYQNtAAAAEGZjaujopxRZWiHuQLZfzfQ="),
      "automaton_transitions" =>
        Base.decode64!(
          "g3QAAAADaAJhAG0AAAADbmV3YQFoAmEBbQAAAAlpbnRlcmZhY2VhAmgCYQJtAAAABXZhbHVlYQM="
        )
    }

    insert_into_interface_4_prepared = Xandra.prepare!(conn, @insert_into_interface_4)

    Xandra.execute!(conn, insert_into_interface_4_prepared, insert_into_interface_4_params)

    Enum.each(@insert_endpoints, fn query ->
      Xandra.execute!(conn, query)
    end)

    Enum.each(@insert_values, fn query ->
      Xandra.execute!(conn, query)
    end)

    :ok
  end

  def destroy_local_test_keyspace(conn) do
    Xandra.execute(conn, "DROP KEYSPACE autotestrealm;")
    :ok
  end

  def await_cluster_connected!(cluster, tries \\ 10) do
    fun = &Xandra.execute!(&1, "SELECT * FROM system.local")

    with {:error, %Xandra.ConnectionError{}} <- Xandra.Cluster.run(cluster, _options = [], fun) do
      if tries > 0 do
        Process.sleep(100)
        await_cluster_connected!(cluster, tries - 1)
      else
        raise("Connection to the cluster failed")
      end
    end
  end
end

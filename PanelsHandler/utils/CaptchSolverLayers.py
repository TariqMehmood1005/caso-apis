import os

os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import tensorflow as tf
import logging

tf.get_logger().setLevel(logging.ERROR)


# Creating Model
@tf.keras.utils.register_keras_serializable(package="CTCBatch")
def ctc_batch_cost(y_true, y_prediction, input_length, label_length):
    label_length = tf.keras.ops.cast(tf.keras.ops.squeeze(label_length, axis=-1), dtype="int32")
    input_length = tf.keras.ops.cast(tf.keras.ops.squeeze(input_length, axis=-1), dtype="int32")
    sparse_labels = tf.keras.ops.cast(
        ctc_label_dense_to_sparse(y_true, label_length), dtype="int32"
    )
    y_prediction = tf.keras.ops.log(tf.keras.ops.transpose(y_prediction, axes=[1, 0, 2]) + tf.keras.backend.epsilon())
    return tf.keras.ops.expand_dims(
        tf.compat.v1.nn.ctc_loss(
            inputs=y_prediction, labels=sparse_labels, sequence_length=input_length
        ),
        1,
    )


@tf.keras.utils.register_keras_serializable(package="CTCLabel")
def ctc_label_dense_to_sparse(labels, label_lengths):
    label_shape = tf.keras.ops.shape(labels)
    num_batches_tns = tf.keras.ops.stack([label_shape[0]])
    max_num_labels_tns = tf.keras.ops.stack([label_shape[1]])

    def range_less_than(old_input, current_input):
        return tf.keras.ops.expand_dims(tf.keras.ops.arange(tf.keras.ops.shape(old_input)[1]), 0) < tf.fill(
            max_num_labels_tns, current_input
        )
    init = tf.keras.ops.cast(tf.fill([1, label_shape[1]], 0), dtype="bool")
    dense_mask = tf.compat.v1.scan(
        range_less_than, label_lengths, initializer=init, parallel_iterations=1
    )
    dense_mask = dense_mask[:, 0, :]
    label_array = tf.keras.ops.reshape(
        tf.keras.ops.tile(tf.keras.ops.arange(0, label_shape[1]), num_batches_tns), label_shape
    )
    label_ind = tf.compat.v1.boolean_mask(label_array, dense_mask)
    batch_array = tf.keras.ops.transpose(
        tf.keras.ops.reshape(
            tf.keras.ops.tile(tf.keras.ops.arange(0, label_shape[0]), max_num_labels_tns),
            tf.reverse(label_shape, [0]),
        )
    )
    batch_ind = tf.compat.v1.boolean_mask(batch_array, dense_mask)
    indices = tf.keras.ops.transpose(
        tf.keras.ops.reshape(tf.keras.ops.concatenate([batch_ind, label_ind], axis=0), [2, -1])
    )
    vals_sparse = tf.compat.v1.gather_nd(labels, indices)
    return tf.SparseTensor(
        tf.keras.ops.cast(indices, dtype="int64"),
        vals_sparse,
        tf.keras.ops.cast(label_shape, dtype="int64")
    )


@tf.keras.utils.register_keras_serializable(package="CTCLayer")
class CTCLayer(tf.keras.layers.Layer):
    def __init__(self, name=None, **kwargs):
        self.name = name
        super().__init__(name=name, **kwargs)
        self.loss_fn = ctc_batch_cost

    def get_config(self):
        config = super().get_config().copy()
        config.update(
            {
                "name": self.name
            }
        )
        return config

    @classmethod
    def from_config(cls,config):
        return cls(**config)

    def call(self, y_true, y_prediction):
        batch_len = tf.keras.ops.cast(tf.keras.ops.shape(y_true)[0], dtype="int64")
        input_length = tf.keras.ops.cast(tf.keras.ops.shape(y_prediction)[1], dtype="int64")
        label_length = tf.keras.ops.cast(tf.keras.ops.shape(y_true)[1], dtype="int64")
        input_length = input_length * tf.keras.ops.ones(shape=(batch_len, 1), dtype="int64")
        label_length = label_length * tf.keras.ops.ones(shape=(batch_len, 1), dtype="int64")
        loss = self.loss_fn(y_true, y_prediction, input_length, label_length)
        self.add_loss(loss)
        return y_prediction
